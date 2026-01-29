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

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

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

const apiLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
const uploadLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
app.use('/api/', apiLimiter);

const JWT_SECRET = process.env.JWT_SECRET || 'army_secret_key_1234';

// ==========================================
// 2. Database & Cloudinary
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
// 3. Helper Functions
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
        if (rule.required && (!value || value.trim() === '')) return { valid: false, message: `${field} is required` };
        if (rule.minLength && value.length < rule.minLength) return { valid: false, message: `${field} too short` };
        if (rule.maxLength && value.length > rule.maxLength) return { valid: false, message: `${field} too long` };
    }
    return { valid: true };
}

async function logAction(userId, username, action, details, req) {
    try {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown';
        await pool.query('INSERT INTO Logs (user_id, username, action, details, ip_address) VALUES (?, ?, ?, ?, ?)', [userId, username, action, details, ip]);
    } catch (err) { console.error('Log Error:', err.message); }
}

function getPublicIdFromUrl(url) {
    try { return url.split('/').slice(-2).join('/').split('.')[0]; } catch (e) { return null; }
}

async function getCloudinaryUsage() {
    try {
        const result = await new Promise((resolve, reject) => {
            cloudinary.api.usage((error, result) => {
                if (error) reject(error); else resolve(result);
            });
        });
        return {
            used_bytes: result.storage?.usage || 0,
            used_readable: (result.storage.usage / (1024*1024)).toFixed(2) + ' MB',
            limit_bytes: result.storage?.limit || 26843545600,
            limit_readable: (result.storage.limit / (1024*1024*1024)).toFixed(2) + ' GB',
            usage_percent: result.storage?.usage ? ((result.storage.usage / result.storage.limit) * 100).toFixed(4) : 0,
            plan: result.plan || 'Free'
        };
    } catch (error) { return { used_readable: 'N/A', limit_readable: 'N/A', usage_percent: 0, plan: 'Unknown' }; }
}

// ==========================================
// 4. API Routes
// ==========================================

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// 🔥🔥🔥 PUBLIC ROUTES (สำหรับ Index.html - สำคัญมาก!) 🔥🔥🔥

// 1. ดึงรูปภาพสาธารณะ
app.get('/public/photos', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
    const offset = (page - 1) * limit;

    try {
        const [results] = await pool.query(`
            SELECT Photos.*, Categories.name as activity_name 
            FROM Photos 
            LEFT JOIN Categories ON Photos.category_id = Categories.category_id 
            WHERE status='approved' AND is_deleted=0 
            ORDER BY upload_date DESC LIMIT ? OFFSET ?`, 
            [limit, offset]
        );

        const photos = results.map(p => ({
            id: p.photo_id,
            url: p.file_path,
            original_url: p.file_path,
            filename: p.file_name,
            activity: p.activity_name || 'กิจกรรมทั่วไป',
            date: p.upload_date
        }));
        res.json(photos);
    } catch (err) {
        console.error('Public photos error:', err);
        res.status(500).json({ error: 'Failed to fetch public photos' });
    }
});

// 2. ดึงหมวดหมู่สาธารณะ
app.get('/public/categories', async (req, res) => {
    try {
        const [results] = await pool.query('SELECT * FROM Categories ORDER BY created_at DESC');
        res.json(results);
    } catch (err) {
        res.status(500).json({ error: 'Failed to fetch categories' });
    }
});

// --- PRIVATE ROUTES (สำหรับ Admin.html) ---

app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    const v = validateInput(req.body, { username: { required: true, minLength: 8 }, password: { required: true, minLength: 8 } });
    if (!v.valid) return res.status(400).json(v);

    try {
        const hash = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO Users (username, password, role) VALUES (?, ?, ?)', [username, hash, role || 'uploader']);
        res.status(201).json({ message: 'Success' });
    } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Username exists' });
        res.status(500).json({ error: 'Register failed' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [u] = await pool.query('SELECT * FROM Users WHERE username = ?', [username]);
        if (!u.length || !(await bcrypt.compare(password, u[0].password))) return res.status(401).json({ message: 'Invalid credentials' });
        const token = jwt.sign({ id: u[0].user_id, role: u[0].role }, JWT_SECRET, { expiresIn: '1d' });
        await logAction(u[0].user_id, u[0].username, 'Login', 'Success', req);
        res.json({ message: 'Success', token, user: { user_id: u[0].user_id, username: u[0].username, role: u[0].role } });
    } catch (e) { res.status(500).json({ error: 'Login failed' }); }
});

app.post('/upload', uploadLimiter, authenticateToken, upload.array('photos', 30), async (req, res) => {
    if (!req.files || !req.files.length) return res.status(400).json({ message: 'No files' });
    const { category_name } = req.body;
    try {
        const [u] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [req.user.id]);
        let catId;
        const [c] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [category_name]);
        if (c.length) catId = c[0].category_id;
        else { const [r] = await pool.query('INSERT INTO Categories (name) VALUES (?)', [category_name]); catId = r.insertId; }

        const val = req.files.map(f => [f.originalname, f.path, f.path, req.user.id, catId, 'approved']);
        await pool.query('INSERT INTO Photos (file_name, file_path, thumbnail_path, uploader_id, category_id, status) VALUES ?', [val]);
        await logAction(req.user.id, u[0].username, 'Upload', `${req.files.length} photos`, req);
        res.status(201).json({ message: 'Uploaded' });
    } catch (e) { res.status(500).json({ error: 'Upload failed' }); }
});

// Admin/Uploader Photos (Authenticated)
app.get('/photos', authenticateToken, async (req, res) => {
    const { page = 1, limit = 50, search = '', category = '' } = req.query;
    const offset = (page - 1) * limit;
    let sql = `SELECT Photos.*, Users.username, Categories.name AS activity_name FROM Photos LEFT JOIN Users ON Photos.uploader_id = Users.user_id LEFT JOIN Categories ON Photos.category_id = Categories.category_id WHERE Photos.status = 'approved' AND Photos.is_deleted = 0`;
    const params = [];

    if (req.user.role !== 'admin') { sql += ` AND Photos.uploader_id = ?`; params.push(req.user.id); }
    if (search) { sql += ` AND (Photos.file_name LIKE ? OR Users.username LIKE ?)`; params.push(`%${search}%`, `%${search}%`); }
    if (category) { sql += ` AND Categories.name = ?`; params.push(category); }
    
    sql += ` ORDER BY Photos.upload_date DESC LIMIT ? OFFSET ?`;
    params.push(parseInt(limit), parseInt(offset));

    try {
        const [r] = await pool.query(sql, params);
        res.json(r.map(p => ({ id: p.photo_id, url: p.file_path, filename: p.file_name, uploader: p.username, activity: p.activity_name, date: p.upload_date })));
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

// Admin/Uploader Stats (Authenticated)
app.get('/stats', authenticateToken, async (req, res) => {
    try {
        if (req.user.role === 'admin') await pool.query('DELETE FROM Categories WHERE category_id NOT IN (SELECT DISTINCT category_id FROM Photos)');
        
        let totalSql, trashSql, catSql = 'SELECT COUNT(*) as count FROM Categories';
        let params = [];

        if (req.user.role === 'admin') {
            totalSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 0';
            trashSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 1';
        } else {
            totalSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 0 AND uploader_id = ?';
            trashSql = 'SELECT COUNT(*) as count FROM Photos WHERE is_deleted = 1 AND uploader_id = ?';
            params = [req.user.id];
        }

        const [[{ count: total }]] = await pool.query(totalSql, params);
        const [[{ count: trash }]] = await pool.query(trashSql, params);
        const [[{ count: cats }]] = await pool.query(catSql);

        res.json({ total_photos: total, total_categories: cats, trash_count: trash });
    } catch (e) { res.status(500).json({ error: 'Error' }); }
});

// Categories for Admin (Authenticated)
app.get('/categories', authenticateToken, async (req, res) => {
    try { const [r] = await pool.query('SELECT * FROM Categories ORDER BY created_at DESC'); res.json(r); } catch (e) { res.status(500).json({ error: 'Error' }); }
});

// ... (Rest of Admin/User management routes - Same as before)
app.put('/photos/:id/details', authenticateToken, adminOnly, async (req, res) => {
    const { category_name, custom_date } = req.body;
    try {
        let catId;
        const [c] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [category_name]);
        if(c.length) catId=c[0].category_id; else { const [r]=await pool.query('INSERT INTO Categories (name) VALUES (?)',[category_name]); catId=r.insertId; }
        await pool.query('UPDATE Photos SET category_id=?, upload_date=? WHERE photo_id=?', [catId, custom_date, req.params.id]);
        res.json({ message: 'Updated' });
    } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.put('/photos/:id/rename', authenticateToken, adminOnly, async (req, res) => {
    try { await pool.query('UPDATE Photos SET file_name=? WHERE photo_id=?', [req.body.new_name, req.params.id]); res.json({ message: 'Renamed' }); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.delete('/photos/:id/soft-delete', authenticateToken, adminOnly, async (req, res) => {
    try { await pool.query('UPDATE Photos SET is_deleted=1 WHERE photo_id=?', [req.params.id]); res.json({ message: 'Deleted' }); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.post('/photos/bulk-delete', authenticateToken, adminOnly, async (req, res) => {
    try { await pool.query('UPDATE Photos SET is_deleted=1 WHERE photo_id IN (?)', [req.body.photo_ids]); res.json({ message: 'Deleted' }); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.get('/photos/trash', authenticateToken, adminOnly, async (req, res) => {
    try { const [r] = await pool.query('SELECT * FROM Photos WHERE is_deleted=1 ORDER BY upload_date DESC'); res.json(r.map(p=>({id:p.photo_id, url:p.file_path, filename:p.file_name}))); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.post('/photos/trash/restore', authenticateToken, adminOnly, async (req, res) => {
    try { await pool.query('UPDATE Photos SET is_deleted=0 WHERE photo_id IN (?)', [req.body.photo_ids]); res.json({ message: 'Restored' }); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.delete('/photos/trash/empty', authenticateToken, adminOnly, async (req, res) => {
    try {
        const [p] = await pool.query('SELECT file_path FROM Photos WHERE photo_id IN (?)', [req.body.photo_ids]);
        for(const x of p) { const pid = getPublicIdFromUrl(x.file_path); if(pid) cloudinary.uploader.destroy(pid).catch(()=>{}); }
        await pool.query('DELETE FROM Photos WHERE photo_id IN (?)', [req.body.photo_ids]);
        res.json({ message: 'Permanently deleted' });
    } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.put('/profile/password', authenticateToken, async (req, res) => {
    try {
        const [u] = await pool.query('SELECT * FROM Users WHERE user_id=?', [req.user.id]);
        if(!await bcrypt.compare(req.body.oldPassword, u[0].password)) return res.status(400).json({ message: 'Wrong password' });
        const h = await bcrypt.hash(req.body.newPassword, 10);
        await pool.query('UPDATE Users SET password=? WHERE user_id=?', [h, req.user.id]);
        res.json({ message: 'Success' });
    } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.put('/profile/username', authenticateToken, async (req, res) => {
    try { await pool.query('UPDATE Users SET username=? WHERE user_id=?', [req.body.newUsername, req.user.id]); res.json({ message: 'Success' }); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.get('/logs', authenticateToken, adminOnly, async (req, res) => {
    try { const [r] = await pool.query('SELECT * FROM Logs ORDER BY created_at DESC LIMIT 100'); res.json(r); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.get('/users', authenticateToken, adminOnly, async (req, res) => {
    try { const [r] = await pool.query('SELECT user_id, username, role, created_at FROM Users'); res.json(r); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.post('/users', authenticateToken, adminOnly, async (req, res) => {
    try { const h = await bcrypt.hash(req.body.password, 10); await pool.query('INSERT INTO Users (username, password, role) VALUES (?, ?, ?)', [req.body.username, h, req.body.role]); res.json({ message: 'Success' }); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.delete('/users/:id', authenticateToken, adminOnly, async (req, res) => {
    try { await pool.query('DELETE FROM Users WHERE user_id=?', [req.params.id]); res.json({ message: 'Deleted' }); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.put('/users/:id/reset', authenticateToken, adminOnly, async (req, res) => {
    try { const h = await bcrypt.hash(req.body.newPassword, 10); await pool.query('UPDATE Users SET password=? WHERE user_id=?', [h, req.params.id]); res.json({ message: 'Success' }); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.put('/users/:id/username', authenticateToken, adminOnly, async (req, res) => {
    try { await pool.query('UPDATE Users SET username=? WHERE user_id=?', [req.body.newUsername, req.params.id]); res.json({ message: 'Success' }); } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.get('/storage/usage', authenticateToken, adminOnly, async (req, res) => {
    try {
        const c = await getCloudinaryUsage();
        const [[{count:a}]] = await pool.query('SELECT COUNT(*) as count FROM Photos WHERE is_deleted=0');
        const [[{count:t}]] = await pool.query('SELECT COUNT(*) as count FROM Photos WHERE is_deleted=1');
        const [l] = await pool.query(`SELECT c.name as category_name, COUNT(p.photo_id) as photo_count, MAX(p.upload_date) as last_update FROM Categories c LEFT JOIN Photos p ON c.category_id = p.category_id AND p.is_deleted = 0 WHERE c.category_id IN (SELECT DISTINCT category_id FROM Photos WHERE is_deleted = 0) GROUP BY c.category_id, c.name ORDER BY last_update DESC LIMIT 5`);
        res.json({ cloudinary: c, database: { active_photos: a, trash_photos: t, total_photos: a+t }, latest_categories: l });
    } catch(e) { res.status(500).json({ error: 'Error' }); }
});
app.get('/storage/average', authenticateToken, async (req, res) => {
    try {
        const r = await cloudinary.api.resources({ type: 'upload', prefix: 'army_gallery/', max_results: 100 });
        let tb = 0; r.resources.forEach(x => tb += x.bytes);
        const avg = r.resources.length ? tb / r.resources.length : 0;
        res.json({ average_bytes: Math.round(avg), average_readable: formatBytes(avg), sample_size: r.resources.length });
    } catch(e) { res.json({ average_readable: '0 B' }); }
});
app.get('/download-zip/:categoryName', async (req, res) => {
    try {
        const [c] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [req.params.categoryName]);
        if (!c.length) return res.status(404).send('Not found');
        const [p] = await pool.query('SELECT file_path, file_name FROM Photos WHERE category_id = ? AND status="approved" AND is_deleted = 0', [c[0].category_id]);
        if (!p.length) return res.status(404).send('No photos');
        const archive = archiver('zip', { zlib: { level: 9 } });
        res.attachment(`${req.params.categoryName}.zip`);
        archive.pipe(res);
        for (const photo of p) { await new Promise((resolve) => { https.get(photo.file_path, (res) => { archive.append(res, { name: photo.file_name }); res.on('end', resolve); res.on('error', resolve); }).on('error', resolve); }); }
        archive.finalize();
    } catch (e) { res.status(500).send('Error'); }
});

app.use((req, res) => { res.status(404).json({ message: 'Route not found' }); });
app.use((err, req, res, next) => { console.error('Server error:', err); res.status(500).json({ error: 'Internal server error' }); });

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));