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

const app = express();

// ✅ CORS Configuration
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// ✅ Cache Control
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    next();
});

// ✅ ปรับ Rate Limiting ให้เหมาะสม
const apiLimiter = rateLimit({ 
    windowMs: 15 * 60 * 1000, 
    max: 100, // ลดจาก 1000 เหลือ 100
    message: 'Too many requests from this IP'
});

const uploadLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10, // อนุญาตอัปโหลด 10 ครั้ง/15 นาที
    message: 'Too many uploads'
});

app.use('/api/', apiLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'army_secret_key_1234';

// ✅ Cloudinary Config
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// ✅ ปรับ Cloudinary Storage ให้บีบอัดเพิ่ม
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'army_gallery',
        allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
        transformation: [
            { width: 1920, height: 1080, crop: "limit" }, // จำกัดขนาดสูงสุด
            { quality: "auto:good" }, // บีบอัดอัตโนมัติ
            { fetch_format: "auto" }
        ]
    },
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 } // จำกัด 10MB/ไฟล์
});

// ✅ Database Connection Pool
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 4000,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME || 'army_photo_gallery',
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true },
    multipleStatements: false, // ป้องกัน SQL Injection
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// ✅ Test DB Connection
(async () => {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Connected to TiDB Cloud Successfully!');
        connection.release();
    } catch (err) { 
        console.error('❌ Database Connection Failed:', err);
        process.exit(1);
    }
})();

// ✅ Middleware: Authentication
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid token' });
        req.user = user;
        next();
    });
}

// ✅ Middleware: Admin Only
function adminOnly(req, res, next) {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ message: 'Admin access required' });
    }
    next();
}

// ✅ Input Validation Helper
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

// ✅ Logging Function
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

// ✅ Cloudinary Helper
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

// ==================== ROUTES ====================

app.get('/', (req, res) => { 
    res.sendFile(path.join(__dirname, 'index.html')); 
});

// ✅ Register
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    
    const validation = validateInput(req.body, {
        username: { required: true, minLength: 3, maxLength: 50 },
        password: { required: true, minLength: 6, maxLength: 100 }
    });
    
    if (!validation.valid) {
        return res.status(400).json({ message: validation.message });
    }
    
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            'INSERT INTO Users (username, password, role) VALUES (?, ?, ?)', 
            [username, hashedPassword, role || 'uploader']
        );
        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ!' });
    } catch (err) { 
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Username already exists' });
        }
        res.status(500).json({ error: 'Registration failed' }); 
    }
});

// ✅ Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    
    const validation = validateInput(req.body, {
        username: { required: true },
        password: { required: true }
    });
    
    if (!validation.valid) {
        return res.status(400).json({ message: validation.message });
    }
    
    try {
        const [users] = await pool.query(
            'SELECT * FROM Users WHERE username = ?', 
            [username]
        );
        
        if (users.length === 0) {
            return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        }
        
        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        
        if (!isMatch) {
            return res.status(401).json({ message: 'รหัสผิด' });
        }
        
        const token = jwt.sign(
            { id: user.user_id, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '1d' }
        );
        
        await logAction(user.user_id, user.username, 'Login', 'เข้าสู่ระบบสำเร็จ', req);
        
        res.json({ 
            message: 'สำเร็จ', 
            token, 
            user: {
                user_id: user.user_id,
                username: user.username,
                role: user.role
            }
        });
    } catch (err) { 
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' }); 
    }
});

// ✅ Upload with Authentication
app.post('/upload', uploadLimiter, authenticateToken, upload.array('photos', 30), async (req, res) => {
    if (!req.files || req.files.length === 0) {
        return res.status(400).json({ message: 'เลือกรูปก่อน' });
    }
    
    const uploader_id = req.user.id;
    const category_name = req.body.category_name?.trim();
    
    if (!category_name) {
        return res.status(400).json({ message: 'ใส่ชื่อกิจกรรม' });
    }

    try {
        const [users] = await pool.query(
            'SELECT username FROM Users WHERE user_id = ?', 
            [uploader_id]
        );
        const uploaderName = users[0] ? users[0].username : 'Unknown';
        
        let catId;
        const [cats] = await pool.query(
            'SELECT category_id FROM Categories WHERE name = ?', 
            [category_name]
        );
        
        if (cats.length > 0) {
            catId = cats[0].category_id;
        } else {
            const [result] = await pool.query(
                'INSERT INTO Categories (name) VALUES (?)', 
                [category_name]
            );
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
        
        await pool.query(
            'INSERT INTO Photos (file_name, file_path, thumbnail_path, uploader_id, category_id, status) VALUES ?', 
            [values]
        );
        
        await logAction(
            uploader_id, 
            uploaderName, 
            'Upload', 
            `อัปโหลด ${req.files.length} รูป (Auto Approve)`, 
            req
        );
        
        res.status(201).json({ 
            message: `อัปโหลดสำเร็จ ${req.files.length} รูป` 
        });
    } catch (err) { 
        console.error('Upload error:', err); 
        res.status(500).json({ error: 'Upload failed' }); 
    }
});

// ✅ Get Photos with Pagination
app.get('/photos', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 50, 1000); // จำกัดไม่เกิน 1000
    const offset = (page - 1) * limit;
    
    const sql = `
        SELECT Photos.*, Users.username, Categories.name AS activity_name 
        FROM Photos 
        LEFT JOIN Users ON Photos.uploader_id = Users.user_id
        LEFT JOIN Categories ON Photos.category_id = Categories.category_id
        WHERE Photos.status = 'approved' AND Photos.is_deleted = 0 
        ORDER BY Photos.upload_date DESC 
        LIMIT ? OFFSET ?
    `;
    
    try {
        const [results] = await pool.query(sql, [limit, offset]);
        
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

// ✅ Get Trash (Admin Only)
app.get('/photos/trash', authenticateToken, adminOnly, async (req, res) => {
    try {
        const [results] = await pool.query(
            'SELECT * FROM Photos WHERE is_deleted = 1 ORDER BY upload_date DESC'
        );
        
        const photos = results.map(p => ({ 
            id: p.photo_id, 
            url: p.file_path, 
            filename: p.file_name 
        }));
        
        res.json(photos);
    } catch (err) { 
        console.error('Get trash error:', err);
        res.status(500).json({ error: 'Failed to fetch trash' }); 
    }
});

// ✅ Soft Delete (Admin Only)
app.delete('/photos/:id', authenticateToken, adminOnly, async (req, res) => {
    try {
        await pool.query(
            'UPDATE Photos SET is_deleted = 1 WHERE photo_id = ?', 
            [req.params.id]
        );
        res.json({ message: 'Moved to trash' });
    } catch (err) { 
        res.status(500).json({ error: 'Delete failed' }); 
    }
});

// ✅ Restore Photo (Admin Only)
app.put('/photos/:id/restore', authenticateToken, adminOnly, async (req, res) => {
    try {
        await pool.query(
            'UPDATE Photos SET is_deleted = 0 WHERE photo_id = ?', 
            [req.params.id]
        );
        res.json({ message: 'Restored' });
    } catch (err) { 
        res.status(500).json({ error: 'Restore failed' }); 
    }
});

// ✅ Permanent Delete (Admin Only)
app.delete('/photos/:id/permanent', authenticateToken, adminOnly, async (req, res) => {
    const photoId = req.params.id;
    
    try {
        const [results] = await pool.query(
            'SELECT file_path, category_id FROM Photos WHERE photo_id = ?', 
            [photoId]
        );
        
        if (results.length === 0) {
            return res.status(404).json({ message: 'Photo not found' });
        }
        
        const photo = results[0];
        const publicId = getPublicIdFromUrl(photo.file_path);
        
        if (publicId) {
            cloudinary.uploader.destroy(publicId, (error, result) => {
                if (error) console.error('Cloudinary delete error:', error);
            });
        }

        await pool.query('DELETE FROM Photos WHERE photo_id = ?', [photoId]);
        
        res.json({ message: 'Permanently deleted' });
    } catch (err) { 
        console.error('Permanent delete error:', err);
        res.status(500).json({ error: 'Delete failed' }); 
    }
});

// ✅ Rename Photo (Admin Only)
app.put('/photos/:id/rename', authenticateToken, adminOnly, async (req, res) => {
    const newName = req.body.new_name?.trim();
    
    if (!newName) {
        return res.status(400).json({ message: 'New name required' });
    }
    
    try {
        await pool.query(
            'UPDATE Photos SET file_name = ? WHERE photo_id = ?', 
            [newName, req.params.id]
        );
        res.json({ message: 'Renamed successfully' });
    } catch (err) { 
        res.status(500).json({ error: 'Rename failed' }); 
    }
});

// ✅ Get Stats with Auto Cleanup
app.get('/stats', async (req, res) => {
    try {
        await pool.query(
            'DELETE FROM Categories WHERE category_id NOT IN (SELECT DISTINCT category_id FROM Photos)'
        );

        const [totalRes] = await pool.query(
            'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 0'
        );
        const [catRes] = await pool.query('SELECT COUNT(*) as count FROM Categories');
        const [trashRes] = await pool.query(
            'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 1'
        );

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

// ✅ Get Categories
app.get('/categories', async (req, res) => { 
    try { 
        const [results] = await pool.query(
            'SELECT * FROM Categories ORDER BY created_at DESC'
        ); 
        res.json(results); 
    } catch (err) { 
        res.status(500).json({ error: 'Failed to fetch categories' }); 
    } 
});

// ✅ Get Logs (Admin Only)
app.get('/logs', authenticateToken, adminOnly, async (req, res) => { 
    try { 
        const [results] = await pool.query(
            'SELECT * FROM Logs ORDER BY created_at DESC LIMIT 50'
        ); 
        res.json(results); 
    } catch (err) { 
        res.status(500).json({ error: 'Failed to fetch logs' }); 
    } 
});

// ✅ Get Users (Admin Only)
app.get('/users', authenticateToken, adminOnly, async (req, res) => { 
    try { 
        const [results] = await pool.query(
            'SELECT user_id, username, role, created_at FROM Users ORDER BY created_at DESC'
        ); 
        res.json(results); 
    } catch (err) { 
        res.status(500).json({ error: 'Failed to fetch users' }); 
    } 
});

// ✅ Add User (Admin Only)
app.post('/users', authenticateToken, adminOnly, async (req, res) => { 
    const validation = validateInput(req.body, {
        username: { required: true, minLength: 3, maxLength: 50 },
        password: { required: true, minLength: 6, maxLength: 100 }
    });
    
    if (!validation.valid) {
        return res.status(400).json({ message: validation.message });
    }
    
    try { 
        const hashedPassword = await bcrypt.hash(req.body.password, 10); 
        await pool.query(
            'INSERT INTO Users (username, password, role) VALUES (?, ?, ?)', 
            [req.body.username, hashedPassword, req.body.role]
        ); 
        res.json({ message: 'User added successfully' }); 
    } catch (err) { 
        if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Username already exists' });
        }
        res.status(500).json({ error: 'Failed to add user' }); 
    } 
});

// ✅ Delete User (Admin Only)
app.delete('/users/:id', authenticateToken, adminOnly, async (req, res) => { 
    try { 
        await pool.query('DELETE FROM Users WHERE user_id = ?', [req.params.id]); 
        res.json({ message: 'User deleted' }); 
    } catch (err) { 
        res.status(500).json({ error: 'Failed to delete user' }); 
    } 
});

// ✅ Reset Password (Admin Only)
app.put('/users/:id/reset', authenticateToken, adminOnly, async (req, res) => { 
    try { 
        const hashedPassword = await bcrypt.hash(req.body.newPassword, 10); 
        await pool.query(
            'UPDATE Users SET password = ? WHERE user_id = ?', 
            [hashedPassword, req.params.id]
        ); 
        res.json({ message: 'Password reset successfully' }); 
    } catch (err) { 
        res.status(500).json({ error: 'Password reset failed' }); 
    } 
});

// ✅ Change Username (Admin Only)
app.put('/users/:id/username', authenticateToken, adminOnly, async (req, res) => { 
    try { 
        await pool.query(
            'UPDATE Users SET username = ? WHERE user_id = ?', 
            [req.body.newUsername, req.params.id]
        ); 
        res.json({ message: 'Username changed' }); 
    } catch (err) { 
        res.status(500).json({ error: 'Username change failed' }); 
    } 
});

// ✅ Download ZIP
app.get('/download-zip/:categoryName', async (req, res) => {
    try {
        const [cats] = await pool.query(
            'SELECT category_id FROM Categories WHERE name = ?', 
            [req.params.categoryName]
        );
        
        if (cats.length === 0) {
            return res.status(404).send('Category not found');
        }
        
        const [photos] = await pool.query(
            'SELECT file_path, file_name FROM Photos WHERE category_id = ? AND status = "approved" AND is_deleted = 0', 
            [cats[0].category_id]
        );
        
        if (photos.length === 0) {
            return res.status(404).send('No photos in this category');
        }

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

// ✅ 404 Handler
app.use((req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

// ✅ Error Handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));