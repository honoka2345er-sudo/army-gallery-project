require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const https = require('https');
const archiver = require('archiver');
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

// ==========================================
// 1. ตั้งค่าความปลอดภัยและ Middleware พื้นฐาน
// ==========================================

// อนุญาต CORS (ให้หน้าเว็บเรียก API ได้)
app.use(cors());

// รองรับ JSON ขนาดใหญ่
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ให้บริการไฟล์ Static (หน้าเว็บ HTML)
app.use(express.static(__dirname));

// ตั้งค่า Helmet
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://cdn.jsdelivr.net",
                    "https://npmcdn.com",
                    "https://cdnjs.cloudflare.com"
                ],
                styleSrc: [
                    "'self'",
                    "'unsafe-inline'",
                    "https://fonts.googleapis.com",
                    "https://cdnjs.cloudflare.com",
                    "https://cdn.jsdelivr.net"
                ],
                imgSrc: [
                    "'self'",
                    "data:",
                    "https://res.cloudinary.com"
                ],
                fontSrc: [
                    "'self'",
                    "https://fonts.gstatic.com"
                ],
                connectSrc: ["'self'"],
            },
        },
        crossOriginResourcePolicy: false,
    })
);

app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many requests from this IP'
});

const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    message: 'Too many uploads'
});

app.use('/api/', apiLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'army_secret_key_1234';

// ==========================================
// 2. ตั้งค่า Database และ Cloudinary
// ==========================================

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'army_gallery',
        allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
    },
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }
});

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 4000,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME || 'army_photo_gallery',
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true },
    multipleStatements: false,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

(async () => {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Connected to TiDB Cloud Successfully!');
        connection.release();
    } catch (err) {
        console.error('❌ Database Connection Failed:', err);
    }
})();

// ==========================================
// 3. Helper Functions & Middleware
// ==========================================

function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

function adminOnly(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
}

function validateInput(data, rules) {
    for (const [field, rule] of Object.entries(rules)) {
        const value = data[field];
        if (rule.required && (!value || value.trim() === '')) {
            return { valid: false, message: `${field} is required` };
        }
        if (rule.minLength && value.length < rule.minLength) {
            return { valid: false, message: `${field} too short` };
        }
        if (rule.maxLength && value.length > rule.maxLength) {
            return { valid: false, message: `${field} too long` };
        }
    }
    return { valid: true };
}

async function logAction(userId, username, action, details, req) {
    try {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown';
        await pool.query(
            'INSERT INTO Logs (user_id, username, action, details, ip_address) VALUES (?, ?, ?, ?, ?)',
            [userId, username, action, details, ip]
        );
    } catch (err) {
        console.error('Log Error:', err.message);
    }
}

function getPublicIdFromUrl(url) {
    try {
        const parts = url.split('/');
        const filename = parts.pop();
        const folder = parts.pop();
        return folder + '/' + filename.split('.')[0];
    } catch (e) {
        return null;
    }
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function getCloudinaryUsage() {
    try {
        const result = await new Promise((resolve, reject) => {
            cloudinary.api.usage((error, result) => {
                if (error) reject(error);
                else resolve(result);
            });
        });

        return {
            used_bytes: result.storage?.usage || 0,
            used_readable: formatBytes(result.storage?.usage || 0),
            limit_bytes: result.storage?.limit || 26843545600,
            limit_readable: formatBytes(result.storage?.limit || 26843545600),
            usage_percent: result.storage?.usage && result.storage?.limit
                ? ((result.storage.usage / result.storage.limit) * 100).toFixed(4)
                : 0,
            plan: result.plan || 'Free'
        };
    } catch (error) {
        console.error('Cloudinary usage error:', error.message);
        return { used_readable: 'N/A', limit_readable: 'N/A', usage_percent: 0, plan: 'Unknown' };
    }
}

// ==========================================
// 4. API Routes
// ==========================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// --- Authentication ---

app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    const validation = validateInput(req.body, {
        username: { required: true, minLength: 8, maxLength: 50 },
        password: { required: true, minLength: 8, maxLength: 100 }
    });

    if (!validation.valid) return res.status(400).json({ message: validation.message });

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO Users (username, password, role) VALUES (?, ?, ?)',
            [username, hashedPassword, role || 'uploader']
        );
        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ!' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Username already exists' });
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const validation = validateInput(req.body, {
        username: { required: true },
        password: { required: true }
    });

    if (!validation.valid) return res.status(400).json({ message: validation.message });

    try {
        const [users] = await pool.query('SELECT * FROM Users WHERE username = ?', [username]);
        if (users.length === 0) return res.status(404).json({ message: 'ไม่พบผู้ใช้' });

        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'รหัสผิด' });

        const token = jwt.sign({ id: user.user_id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
        await logAction(user.user_id, user.username, 'Login', 'เข้าสู่ระบบสำเร็จ', req);

        res.json({
            message: 'สำเร็จ',
            token,
            user: { user_id: user.user_id, username: user.username, role: user.role }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

// --- Upload ---

app.post('/upload', uploadLimiter, authenticateToken, upload.array('photos', 30), async (req, res) => {
    if (!req.files || req.files.length === 0) return res.status(400).json({ message: 'เลือกรูปก่อน' });

    const uploader_id = req.user.id;
    const category_name = req.body.category_name?.trim();

    if (!category_name) return res.status(400).json({ message: 'ใส่ชื่อกิจกรรม' });

    try {
        const [users] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [uploader_id]);
        const uploaderName = users[0] ? users[0].username : 'Unknown';

        let catId;
        const [cats] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [category_name]);
        if (cats.length > 0) {
            catId = cats[0].category_id;
        } else {
            const [result] = await pool.query('INSERT INTO Categories (name) VALUES (?)', [category_name]);
            catId = result.insertId;
        }

        const values = req.files.map(file => [
            file.originalname,
            file.path,
            file.path,
            uploader_id,
            catId,
            'approved'
        ]);

        await pool.query('INSERT INTO Photos (file_name, file_path, thumbnail_path, uploader_id, category_id, status) VALUES ?', [values]);
        await logAction(uploader_id, uploaderName, 'Upload', `อัปโหลด ${req.files.length} รูป (Auto Approve)`, req);

        res.status(201).json({ message: `อัปโหลดสำเร็จ ${req.files.length} รูป` });
    } catch (err) {
        console.error('Upload error:', err);
        res.status(500).json({ error: 'Upload failed' });
    }
});

// --- Photos Management (Read/Update) ---

app.get('/photos', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 1000);
    const offset = (page - 1) * limit;
    const search = req.query.search || '';
    const category = req.query.category || '';

    let sql = `
        SELECT Photos.*, Users.username, Categories.name AS activity_name 
        FROM Photos 
        LEFT JOIN Users ON Photos.uploader_id = Users.user_id
        LEFT JOIN Categories ON Photos.category_id = Categories.category_id
        WHERE Photos.status = 'approved' AND Photos.is_deleted = 0 
    `;

    const params = [];

    if (search) {
        sql += ` AND (Photos.file_name LIKE ? OR Users.username LIKE ?)`;
        params.push(`%${search}%`, `%${search}%`);
    }

    if (category) {
        sql += ` AND Categories.name = ?`;
        params.push(category);
    }

    sql += ` ORDER BY Photos.upload_date DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);

    try {
        const [results] = await pool.query(sql, params);
        const photos = results.map(photo => ({
            id: photo.photo_id,
            url: photo.file_path,
            original_url: photo.file_path,
            filename: photo.file_name,
            uploader: photo.username,
            activity: photo.activity_name || 'กิจกรรมทั่วไป',
            date: photo.upload_date
        }));
        res.json(photos);
    } catch (err) {
        console.error('Get photos error:', err);
        res.status(500).json({ error: 'Failed to fetch photos' });
    }
});

app.put('/photos/:id/details', authenticateToken, adminOnly, async (req, res) => {
    const { category_name, custom_date } = req.body;
    const photoId = req.params.id;

    if (!category_name || !custom_date) return res.status(400).json({ message: 'ข้อมูลไม่ครบถ้วน' });

    try {
        let catId;
        const [cats] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [category_name]);
        if (cats.length > 0) {
            catId = cats[0].category_id;
        } else {
            const [result] = await pool.query('INSERT INTO Categories (name) VALUES (?)', [category_name]);
            catId = result.insertId;
        }

        await pool.query('UPDATE Photos SET category_id = ?, upload_date = ? WHERE photo_id = ?', [catId, custom_date, photoId]);
        res.json({ message: 'แก้ไขข้อมูลเรียบร้อย' });
    } catch (err) {
        console.error('Edit details error:', err);
        res.status(500).json({ error: 'แก้ไขข้อมูลล้มเหลว' });
    }
});

app.put('/photos/:id/rename', authenticateToken, adminOnly, async (req, res) => {
    const newName = req.body.new_name?.trim();
    if (!newName) return res.status(400).json({ message: 'New name required' });
    try {
        await pool.query('UPDATE Photos SET file_name = ? WHERE photo_id = ?', [newName, req.params.id]);
        res.json({ message: 'Renamed successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Rename failed' });
    }
});

// 🔥🔥🔥 DELETE/RESTORE (Fixed for Bulk & Single) 🔥🔥🔥

// 1. Soft Delete (Single or Bulk)
app.delete('/photos/:id/soft-delete', authenticateToken, adminOnly, async (req, res) => {
    try {
        await pool.query('UPDATE Photos SET is_deleted = 1 WHERE photo_id = ?', [req.params.id]);
        res.json({ message: 'Moved to trash' });
    } catch (err) {
        res.status(500).json({ error: 'Delete failed' });
    }
});

app.post('/photos/bulk-delete', authenticateToken, adminOnly, async (req, res) => {
    const { photo_ids } = req.body;
    if (!photo_ids || !photo_ids.length) return res.status(400).json({ message: 'No photos selected' });
    try {
        await pool.query('UPDATE Photos SET is_deleted = 1 WHERE photo_id IN (?)', [photo_ids]);
        res.json({ message: 'Bulk deleted successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Bulk delete failed' });
    }
});

// 2. Get Trash
app.get('/photos/trash', authenticateToken, adminOnly, async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM Photos WHERE is_deleted = 1 ORDER BY upload_date DESC');
        const photos = results.map(p => ({ id: p.photo_id, url: p.file_path, filename: p.file_name }));
        res.json(photos);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch trash' });
    }
});

// 3. Restore (Bulk)
app.post('/photos/trash/restore', authenticateToken, adminOnly, async (req, res) => {
    const { photo_ids } = req.body;
    if (!photo_ids || !photo_ids.length) return res.status(400).json({ message: 'No photos to restore' });

    try {
        await pool.query('UPDATE Photos SET is_deleted = 0 WHERE photo_id IN (?)', [photo_ids]);
        res.json({ message: 'Restored successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Restore failed' });
    }
});

// 4. Permanent Delete (Bulk)
app.delete('/photos/trash/empty', authenticateToken, adminOnly, async (req, res) => {
    const { photo_ids } = req.body;
    if (!photo_ids || !photo_ids.length) return res.status(400).json({ message: 'No photos to delete' });

    try {
        const [photos] = await pool.query('SELECT file_path, category_id FROM Photos WHERE photo_id IN (?)', [photo_ids]);
        
        for (const photo of photos) {
            const publicId = getPublicIdFromUrl(photo.file_path);
            if (publicId) {
                cloudinary.uploader.destroy(publicId).catch(err => console.error('Cloudinary del error', err));
            }
        }

        await pool.query('DELETE FROM Photos WHERE photo_id IN (?)', [photo_ids]);
        res.json({ message: 'Permanently deleted' });
    } catch (err) {
        console.error('Permanent delete error:', err);
        res.status(500).json({ error: 'Delete failed' });
    }
});

// --- Profile Management (User) ---

app.put('/profile/password', authenticateToken, async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ message: 'กรุณากรอกข้อมูลให้ครบ' });

    try {
        const [users] = await pool.query('SELECT * FROM Users WHERE user_id = ?', [req.user.id]);
        if (users.length === 0) return res.status(404).json({ message: 'ไม่พบผู้ใช้' });

        const user = users[0];
        const isMatch = await bcrypt.compare(oldPassword, user.password);
        if (!isMatch) return res.status(400).json({ message: 'รหัสผ่านเดิมไม่ถูกต้อง' });

        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await pool.query('UPDATE Users SET password = ? WHERE user_id = ?', [hashedPassword, req.user.id]);
        res.json({ message: 'เปลี่ยนรหัสผ่านสำเร็จ' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.put('/profile/username', authenticateToken, async (req, res) => {
    const { newUsername } = req.body;
    if (!newUsername) return res.status(400).json({ message: 'กรุณากรอกชื่อใหม่' });

    try {
        await pool.query('UPDATE Users SET username = ? WHERE user_id = ?', [newUsername, req.user.id]);
        res.json({ message: 'เปลี่ยนชื่อสำเร็จ' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'ชื่อนี้มีคนใช้แล้ว' });
        res.status(500).json({ error: err.message });
    }
});

// 🔥🔥🔥 FIXED STATS (Separated Logic for Admin/Uploader) 🔥🔥🔥

app.get('/stats', authenticateToken, async (req, res) => {
    try {
        // Only Admin can clean up categories
        if (req.user.role === 'admin') {
            await pool.query('DELETE FROM Categories WHERE category_id NOT IN (SELECT DISTINCT category_id FROM Photos)');
        }

        let totalSql, trashSql, catSql;
        let params = [];

        if (req.user.role === 'admin') {
            // Admin: See Global
            totalSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 0';
            trashSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 1';
            catSql = 'SELECT COUNT(*) as count FROM Categories';
        } else {
            // Uploader: See Personal
            totalSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 0 AND uploader_id = ?';
            trashSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 1 AND uploader_id = ?';
            catSql = 'SELECT COUNT(*) as count FROM Categories'; 
            params = [req.user.id];
        }

        const [totalRes] = await pool.query(totalSql, params);
        const [trashRes] = await pool.query(trashSql, params);
        const [catRes] = await pool.query(catSql);

        res.json({
            total_photos: totalRes[0].count,
            pending_photos: 0,
            total_categories: catRes[0].count,
            trash_count: trashRes[0].count
        });
    } catch (err) {
        console.error('Stats error:', err);
        res.status(500).json({ error: 'Failed to get stats' });
    }
});

app.get('/storage/usage', authenticateToken, adminOnly, async (req, res) => {
    try {
        const cloudinaryData = await getCloudinaryUsage();
        const [photosCount] = await pool.query('SELECT COUNT(*) as total FROM Photos WHERE is_deleted = 0');
        const [trashCount] = await pool.query('SELECT COUNT(*) as total FROM Photos WHERE is_deleted = 1');
        const [latestStats] = await pool.query(`
            SELECT c.name as category_name, COUNT(p.photo_id) as photo_count, MAX(p.upload_date) as last_update
            FROM Categories c
            LEFT JOIN Photos p ON c.category_id = p.category_id AND p.is_deleted = 0
            WHERE c.category_id IN (SELECT DISTINCT category_id FROM Photos WHERE is_deleted = 0)
            GROUP BY c.category_id, c.name
            ORDER BY last_update DESC
            LIMIT 5
        `);

        res.json({
            cloudinary: cloudinaryData,
            database: {
                active_photos: photosCount[0].total,
                trash_photos: trashCount[0].total,
                total_photos: photosCount[0].total + trashCount[0].total
            },
            latest_categories: latestStats
        });
    } catch (error) {
        console.error('❌ Storage usage error:', error);
        res.status(500).json({ error: 'Failed to get storage usage' });
    }
});

app.get('/storage/average', authenticateToken, async (req, res) => {
    try {
        const result = await cloudinary.api.resources({ type: 'upload', prefix: 'army_gallery/', max_results: 100 });
        let totalBytes = 0, count = 0;
        if (result.resources && result.resources.length > 0) {
            result.resources.forEach(res => { totalBytes += res.bytes; count++; });
        }
        const avgSize = count > 0 ? totalBytes / count : 0;
        res.json({ average_bytes: Math.round(avgSize), average_readable: formatBytes(avgSize), sample_size: count });
    } catch (error) {
        console.error('Average size error:', error);
        res.json({ average_readable: '0 B' });
    }
});

// --- General Data ---

app.get('/categories', authenticateToken, async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM Categories ORDER BY created_at DESC');
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch categories' });
    }
});

app.get('/logs', authenticateToken, adminOnly, async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM Logs ORDER BY created_at DESC LIMIT 100');
        res.json(results);
    } catch (err) {
        console.error('Logs Error:', err);
        res.status(500).json({ error: 'Failed to fetch logs' });
    }
});

// --- User Management (Admin) ---

app.get('/users', authenticateToken, adminOnly, async (req, res) => {
    try {
        const [results] = await pool.query('SELECT user_id, username, role, created_at FROM Users ORDER BY created_at DESC');
        res.json(results);
    } catch (err) {
        console.error('Users Error:', err);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.post('/users', authenticateToken, adminOnly, async (req, res) => {
    const validation = validateInput(req.body, { username: { required: true, minLength: 8, maxLength: 50 }, password: { required: true, minLength: 8, maxLength: 100 } });
    if (!validation.valid) return res.status(400).json({ message: validation.message });

    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        await pool.query('INSERT INTO Users (username, password, role) VALUES (?, ?, ?)', [req.body.username, hashedPassword, req.body.role]);
        res.json({ message: 'User added successfully' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Username already exists' });
        res.status(500).json({ error: 'Failed to add user' });
    }
});

app.delete('/users/:id', authenticateToken, adminOnly, async (req, res) => {
    try {
        await pool.query('DELETE FROM Users WHERE user_id = ?', [req.params.id]);
        res.json({ message: 'User deleted' });
    } catch (err) {
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.put('/users/:id/reset', authenticateToken, adminOnly, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10);
        await pool.query('UPDATE Users SET password = ? WHERE user_id = ?', [hashedPassword, req.params.id]);
        res.json({ message: 'Password reset successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Password reset failed' });
    }
});

app.put('/users/:id/username', authenticateToken, adminOnly, async (req, res) => {
    try {
        await pool.query('UPDATE Users SET username = ? WHERE user_id = ?', [req.body.newUsername, req.params.id]);
        res.json({ message: 'Username changed' });
    } catch (err) {
        res.status(500).json({ error: 'Username change failed' });
    }
});

// --- Utils ---

app.get('/download-zip/:categoryName', async (req, res) => {
    try {
        const [cats] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [req.params.categoryName]);
        if (cats.length === 0) return res.status(404).send('Category not found');

        const [photos] = await pool.query('SELECT file_path, file_name FROM Photos WHERE category_id = ? AND status = "approved" AND is_deleted = 0', [cats[0].category_id]);
        if (photos.length === 0) return res.status(404).send('No photos in this category');

        const archive = archiver('zip', { zlib: { level: 9 } });
        res.attachment(`${req.params.categoryName}.zip`);
        archive.pipe(res);

        for (const photo of photos) {
            await new Promise((resolve) => {
                https.get(photo.file_path, (response) => {
                    archive.append(response, { name: photo.file_name });
                    response.on('end', resolve);
                    response.on('error', resolve);
                }).on('error', resolve);
            });
        }
        archive.finalize();
    } catch (err) {
        console.error('ZIP error:', err);
        res.status(500).send('Error creating ZIP');
    }
});

// 404 & Error Handler
app.use((req, res) => { res.status(404).json({ message: 'Route not found' }); });
app.use((err, req, res, next) => { console.error('Server error:', err); res.status(500).json({ error: 'Internal server error' }); });

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));