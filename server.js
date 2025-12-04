require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const https = require('https'); // เพิ่มสำหรับโหลด ZIP
const archiver = require('archiver'); // เพิ่มสำหรับโหลด ZIP

// 🔥 เพิ่มส่วนของ Cloudinary
const cloudinary = require('cloudinary').v2;
const { CloudinaryStorage } = require('multer-storage-cloudinary');

const rateLimit = require('express-rate-limit');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 1000 });
app.use('/api/', limiter);

const JWT_SECRET = process.env.JWT_SECRET || 'army_secret_key_1234';

// ✅ ตั้งค่า Cloudinary
cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET
});

// ✅ ตั้งค่าที่เก็บไฟล์ + บีบอัดภาพ
const storage = new CloudinaryStorage({
    cloudinary: cloudinary,
    params: {
        folder: 'army_gallery',
        allowed_formats: ['jpg', 'png', 'jpeg', 'webp'],
        transformation: [
            { quality: "auto" },
            { fetch_format: "auto" }
        ]
    },
});

const upload = multer({ storage: storage });

// เชื่อมต่อ TiDB Cloud
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 4000,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME || 'army_photo_gallery',
    ssl: { minVersion: 'TLSv1.2', rejectUnauthorized: true },
    multipleStatements: true,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

(async () => {
    try {
        const connection = await pool.getConnection();
        console.log('✅ Connected to TiDB Cloud Successfully!');
        await connection.query('DELETE FROM Categories WHERE category_id NOT IN (SELECT DISTINCT category_id FROM Photos)');
        console.log('🧹 Auto-cleaned empty categories on startup');
        connection.release();
    } catch (err) { console.error('❌ Database Connection Failed:', err); }
})();

async function logAction(userId, username, action, details, req) {
    try {
        const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'Unknown';
        await pool.query('INSERT INTO Logs (user_id, username, action, details, ip_address) VALUES (?, ?, ?, ?, ?)', [userId, username, action, details, ip]);
    } catch (err) { console.error('Log Error:', err.message); }
}

function getPublicIdFromUrl(url) {
    try {
        const parts = url.split('/');
        const filename = parts.pop();
        const folder = parts.pop();
        return folder + '/' + filename.split('.')[0];
    } catch (e) { return null; }
}

app.get('/', (req, res) => { res.sendFile(path.join(__dirname, 'index.html')); });

app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO Users (username, password, role) VALUES (?, ?, ?)', [username, hashedPassword, role || 'uploader']);
        res.status(201).json({ message: 'สมัครสมาชิกสำเร็จ!' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const [users] = await pool.query('SELECT * FROM Users WHERE username = ?', [username]);
        if (users.length === 0) return res.status(404).json({ message: 'ไม่พบผู้ใช้' });
        const user = users[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(401).json({ message: 'รหัสผิด' });
        const token = jwt.sign({ id: user.user_id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
        logAction(user.user_id, user.username, 'Login', 'เข้าสู่ระบบสำเร็จ', req);
        res.json({ message: 'สำเร็จ', token, user });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// 🔥 แก้ไข: อัปโหลดแล้วเป็น Approved ทันที (Auto Approve)
app.post('/upload', upload.array('photos', 20), async (req, res) => {
    if (!req.files || req.files.length === 0) return res.status(400).json({ message: 'เลือกรูปก่อน' });
    const uploader_id = req.body.user_id || 0;
    const category_name = req.body.category_name;
    if (!category_name) return res.status(400).json({ message: 'ใส่ชื่อกิจกรรม' });

    try {
        const [users] = await pool.query('SELECT username FROM Users WHERE user_id = ?', [uploader_id]);
        const uploaderName = users[0] ? users[0].username : 'Unknown';
        let catId;
        const [cats] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [category_name]);
        if (cats.length > 0) catId = cats[0].category_id;
        else {
            const [result] = await pool.query('INSERT INTO Categories (name) VALUES (?)', [category_name]);
            catId = result.insertId;
        }
        
        const values = [];
        for (const file of req.files) {
            // 🔥 ใส่สถานะ 'approved' เข้าไปเลย
            values.push([file.originalname, file.path, file.path, uploader_id, catId, 'approved']);
        }
        
        // 🔥 เพิ่ม column status ในคำสั่ง SQL
        await pool.query('INSERT INTO Photos (file_name, file_path, thumbnail_path, uploader_id, category_id, status) VALUES ?', [values]);
        
        logAction(uploader_id, uploaderName, 'Upload', `อัปโหลด ${req.files.length} รูป (Auto Approve)`, req);
        res.status(201).json({ message: `อัปโหลดสำเร็จ ${req.files.length} รูป` });
    } catch (err) { console.error(err); res.status(500).json({ error: 'Server Error' }); }
});

app.get('/photos', async (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 1000;
    const offset = (page - 1) * limit;
    const sql = `SELECT Photos.*, Users.username, Categories.name AS activity_name FROM Photos 
                 LEFT JOIN Users ON Photos.uploader_id = Users.user_id
                 LEFT JOIN Categories ON Photos.category_id = Categories.category_id
                 WHERE Photos.status = 'approved' AND Photos.is_deleted = 0 
                 ORDER BY Photos.upload_date DESC LIMIT ? OFFSET ?`;
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
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/photos/pending', async (req, res) => { res.json([]); });

app.get('/photos/trash', async (req, res) => {
    try {
        const [results] = await pool.query(`SELECT * FROM Photos WHERE is_deleted = 1 ORDER BY upload_date DESC`);
        const photos = results.map(p => ({ id: p.photo_id, url: p.file_path, filename: p.file_name }));
        res.json(photos);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.put('/photos/:id/status', async (req, res) => {
    try { await pool.query('UPDATE Photos SET status = ? WHERE photo_id = ?', [req.body.status, req.params.id]); res.json({ message: 'Updated' }); } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/photos/:id/rename', async (req, res) => {
    try { await pool.query('UPDATE Photos SET file_name = ? WHERE photo_id = ?', [req.body.new_name, req.params.id]); res.json({ message: 'Renamed' }); } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete('/photos/:id', async (req, res) => {
    try { await pool.query('UPDATE Photos SET is_deleted = 1 WHERE photo_id = ?', [req.params.id]); res.json({ message: 'Trashed' }); } catch (err) { res.status(500).json({ error: err.message }); }
});
app.put('/photos/:id/restore', async (req, res) => {
    try { await pool.query('UPDATE Photos SET is_deleted = 0 WHERE photo_id = ?', [req.params.id]); res.json({ message: 'Restored' }); } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/photos/:id/permanent', async (req, res) => {
    const photoId = req.params.id;
    try {
        const [results] = await pool.query('SELECT file_path, category_id FROM Photos WHERE photo_id = ?', [photoId]);
        if (results.length === 0) return res.status(404).json({ message: 'Not found' });
        const f = results[0];

        const publicId = getPublicIdFromUrl(f.file_path);
        if (publicId) cloudinary.uploader.destroy(publicId, (e,r)=>{});

        await pool.query('DELETE FROM Photos WHERE photo_id = ?', [photoId]);

        if (f.category_id) {
            const [countRes] = await pool.query('SELECT COUNT(*) as count FROM Photos WHERE category_id = ?', [f.category_id]);
            if (countRes[0].count === 0) await pool.query('DELETE FROM Categories WHERE category_id = ?', [f.category_id]);
        }
        res.json({ message: 'Deleted' });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/stats', async (req, res) => {
    try {
        const sql = `SELECT COUNT(*) as total FROM Photos WHERE is_deleted = 0; 
                     SELECT 0 as pending; 
                     SELECT COUNT(*) as cats FROM Categories; 
                     SELECT COUNT(*) as trash FROM Photos WHERE is_deleted = 1;`;
        const [results] = await pool.query(sql);
        res.json({ total_photos: results[0][0].total, pending_photos: 0, total_categories: results[2][0].cats, trash_count: results[3][0].trash });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/categories', async (req, res) => { try { const [results] = await pool.query('SELECT * FROM Categories ORDER BY created_at DESC'); res.json(results); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/logs', async (req, res) => { try { const [results] = await pool.query('SELECT * FROM Logs ORDER BY created_at DESC LIMIT 50'); res.json(results); } catch (err) { res.status(500).json({ error: err.message }); } });
app.get('/users', async (req, res) => { try { const [results] = await pool.query('SELECT user_id, username, role, created_at FROM Users ORDER BY created_at DESC'); res.json(results); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post('/users', async (req, res) => { try { const hashedPassword = await bcrypt.hash(req.body.password, 10); await pool.query('INSERT INTO Users (username, password, role) VALUES (?, ?, ?)', [req.body.username, hashedPassword, req.body.role]); res.json({ message: 'Added' }); } catch (err) { res.status(500).json({ error: 'Error' }); } });
app.delete('/users/:id', async (req, res) => { try { await pool.query('DELETE FROM Users WHERE user_id = ?', [req.params.id]); res.json({ message: 'Deleted' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put('/users/:id/reset', async (req, res) => { try { const hashedPassword = await bcrypt.hash(req.body.newPassword, 10); await pool.query('UPDATE Users SET password = ? WHERE user_id = ?', [hashedPassword, req.params.id]); res.json({ message: 'Reset' }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put('/users/:id/username', async (req, res) => { try { await pool.query('UPDATE Users SET username = ? WHERE user_id = ?', [req.body.newUsername, req.params.id]); res.json({ message: 'Username changed' }); } catch (err) { res.status(500).json({ message: 'Error' }); } });

// 🔥 กู้คืนระบบ ZIP
app.get('/download-zip/:categoryName', async (req, res) => {
    try {
        const [cats] = await pool.query('SELECT category_id FROM Categories WHERE name = ?', [req.params.categoryName]);
        if (cats.length === 0) return res.status(404).send('Not found');
        
        const [photos] = await pool.query('SELECT file_path, file_name FROM Photos WHERE category_id = ? AND status = "approved" AND is_deleted = 0', [cats[0].category_id]);
        if (photos.length === 0) return res.status(404).send('No photos');

        const archive = archiver('zip', { zlib: { level: 9 } });
        res.attachment(`${req.params.categoryName}.zip`);
        archive.pipe(res);

        for (const photo of photos) {
            const url = photo.file_path;
            await new Promise((resolve) => {
                https.get(url, (response) => {
                    archive.append(response, { name: photo.file_name });
                    response.on('end', resolve);
                    response.on('error', resolve);
                }).on('error', resolve);
            });
        }
        archive.finalize();
    } catch (err) { console.error(err); res.status(500).send('Error creating ZIP'); }
});

const port = process.env.PORT || 3001;
app.listen(port, () => console.log(`🚀 Server running on port ${port}`));