require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const cloudinary = require('cloudinary').v2;
const multer = require('multer');

// Multer configuration for file uploads
const upload = multer({ storage: multer.memoryStorage() });

// Cloudinary configuration
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Email configuration
const hasGmailConfig = process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD;
let emailTransporter = null;

if (hasGmailConfig) {
  emailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD
    }
  });
  console.log('Email transporter configured (credentials will be validated on first use)');
} else {
  nodemailer.createTestAccount((err, testAccount) => {
    if (err) {
      console.log('Could not create Ethereal test account:', err.message);
    } else {
      emailTransporter = nodemailer.createTransport({
        host: testAccount.smtp.host,
        port: testAccount.smtp.port,
        secure: testAccount.smtp.secure,
        auth: {
          user: testAccount.user,
          pass: testAccount.pass
        }
      });
      console.log('📧 Test email account created');
      console.log('   View emails at:', testAccount.web);
    }
  });
}

// Error handlers
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION:', reason);
});

// CORS configuration
const allowedOrigins = [
  /^http:\/\/localhost:\d+$/,
  /^http:\/\/127\.0\.0\.1:\d+$/,
  /^https:\/\/college-space.*\.vercel\.app$/,
  /^https:\/\/.*\.vercel\.app$/
];

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (allowedOrigins.some((o) => o.test(origin))) {
      return callback(null, true);
    }
    console.log('CORS blocked origin:', origin);
    return callback(new Error('CORS not allowed'), false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  exposedHeaders: ['Content-Type', 'Authorization']
}));

app.options('*', cors());

const jsonLimit = process.env.JSON_LIMIT || '2mb';
app.use(express.json({ limit: jsonLimit }));
app.use(express.urlencoded({ extended: true, limit: jsonLimit }));

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

// Test connection and initialize
let dbConnected = false;

pool.connect(async (err, client, release) => {
  if (err) {
    console.error('Database connection error:', err.message);
    console.error('DATABASE_URL:', process.env.DATABASE_URL ? 'SET' : 'NOT SET');
    console.warn('Server will start but database operations may fail');
  } else {
    console.log('Connected to PostgreSQL database');
    dbConnected = true;
    release();
    try {
      await initializeDatabase();
    } catch (error) {
      console.error('Error initializing database:', error);
    }
  }
});

// Helper functions
const sanitizeNameInput = (input) => {
  if (!input) return '';
  return String(input).replace(/[<>]/g, '').slice(0, 50);
};

const buildAvatar = (first, last) => {
  const firstInitial = first?.[0] || 'С';
  const lastInitial = last?.[0] || 'Т';
  return `${firstInitial}${lastInitial}`.toUpperCase();
};

// Config endpoint
// ============ ROUTES ============

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'College Hub Backend API',
    status: 'running',
    version: '1.0.0',
    endpoints: {
      health: '/api/health',
      config: '/api/config',
      auth: {
        login: 'POST /api/auth/login'
      }
    }
  });
});

app.get('/api/config', (req, res) => {
  const apiUrl = process.env.API_URL || `http://localhost:${PORT}`;
  res.json({ apiUrl });
});

// Health check endpoint
app.get('/api/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');
    res.json({
      status: 'ok',
      database: 'connected',
      timestamp: result.rows[0]
    });
  } catch (error) {
    console.error('Health check error:', error);
    res.status(503).json({
      status: 'error',
      database: 'disconnected',
      error: error.message
    });
  }
});

// Upload endpoint for Cloudinary
app.post('/api/upload', upload.single('file'), async (req, res) => {
  try {
    // Check authorization
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }
    
    try {
      jwt.verify(token, JWT_SECRET);
    } catch (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }

    if (!req.file) {
      return res.status(400).json({ error: 'No file provided' });
    }

    // Check Cloudinary config
    if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
      console.error('Cloudinary not configured');
      return res.status(500).json({ error: 'Cloudinary not configured' });
    }

    const folder = req.body.folder || 'college-hub';
    
    // Upload to Cloudinary
    const result = await new Promise((resolve, reject) => {
      cloudinary.uploader.upload_stream(
        { 
          folder: folder,
          resource_type: 'auto'
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      ).end(req.file.buffer);
    });

    console.log('[Upload] Success:', result.secure_url);

    res.json({
      success: true,
      url: result.secure_url,
      publicId: result.public_id,
      width: result.width,
      height: result.height
    });
  } catch (error) {
    console.error('Upload error:', error);
    res.status(500).json({ error: 'Upload failed', details: error.message });
  }
});

// Authentication middleware
const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
      try {
        if (err) {
          return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
      } catch (e) {
        console.error('Error in token callback:', e);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  } catch (error) {
    console.error('Error in authenticateToken:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Admin middleware
const requireAdmin = async (req, res, next) => {
  try {
    const result = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    if (!result.rows[0].is_admin) {
      return res.status(403).json({ error: 'Admin rights required' });
    }
    next();
  } catch (error) {
    console.error('Error in requireAdmin:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

// Initialize database
async function initializeDatabase() {
  try {
    // Create tables
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        student_id VARCHAR(6) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL,
        role VARCHAR(255),
        is_admin BOOLEAN DEFAULT FALSE,
        avatar VARCHAR(255),
        password VARCHAR(255) NOT NULL,
        joined_clubs TEXT DEFAULT '[]',
        joined_projects TEXT DEFAULT '[]',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS news (
        id SERIAL PRIMARY KEY,
        author VARCHAR(255) NOT NULL,
        author_key VARCHAR(255),
        time VARCHAR(255) NOT NULL,
        time_key VARCHAR(255),
        content TEXT NOT NULL,
        content_key VARCHAR(255),
        tags TEXT,
        tags_keys TEXT,
        likes INTEGER DEFAULT 0,
        comments INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS news_likes (
        id SERIAL PRIMARY KEY,
        news_id INTEGER NOT NULL REFERENCES news(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(news_id, user_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS comments (
        id SERIAL PRIMARY KEY,
        news_id INTEGER NOT NULL REFERENCES news(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        text TEXT NOT NULL,
        author VARCHAR(255) NOT NULL,
        author_id VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS clubs (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        category VARCHAR(255) NOT NULL,
        category_key VARCHAR(255),
        members INTEGER DEFAULT 0,
        description TEXT,
        description_key VARCHAR(255),
        color VARCHAR(50) DEFAULT 'bg-blue-500',
        instagram VARCHAR(255),
        telegram VARCHAR(255),
        whatsapp VARCHAR(255),
        tiktok VARCHAR(255),
        youtube VARCHAR(255),
        website VARCHAR(255),
        creator_id INTEGER REFERENCES users(id),
        creator_name VARCHAR(255),
        photos TEXT DEFAULT '[]',
        background_url VARCHAR(255),
        background_type VARCHAR(50) DEFAULT 'color',
        club_avatar VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS club_memberships (
        id SERIAL PRIMARY KEY,
        club_id INTEGER NOT NULL REFERENCES clubs(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        joined_at TIMESTAMP NOT NULL,
        UNIQUE(club_id, user_id)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        title_key VARCHAR(255),
        status VARCHAR(50) NOT NULL,
        needed TEXT,
        needed_keys TEXT,
        author VARCHAR(255) NOT NULL,
        club_id INTEGER REFERENCES clubs(id),
        background_url VARCHAR(255),
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS schedule (
        id SERIAL PRIMARY KEY,
        date VARCHAR(50) NOT NULL,
        time VARCHAR(50) NOT NULL,
        subject VARCHAR(255) NOT NULL,
        subject_key VARCHAR(255),
        room VARCHAR(50) NOT NULL,
        room_key VARCHAR(255),
        type VARCHAR(50),
        color VARCHAR(50),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS activities (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        club VARCHAR(255) NOT NULL,
        action VARCHAR(255) NOT NULL,
        action_key VARCHAR(255),
        detail TEXT NOT NULL,
        detail_key VARCHAR(255),
        date VARCHAR(50) NOT NULL,
        date_key VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS parliament (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        role VARCHAR(255) NOT NULL,
        role_key VARCHAR(255),
        position VARCHAR(255),
        description TEXT,
        group_name VARCHAR(255),
        avatar VARCHAR(255),
        avatar_url VARCHAR(255),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    console.log('Database schema initialized');
    await seedDatabase();
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Seed database
async function seedDatabase() {
  try {
    const userCount = await pool.query('SELECT COUNT(*) FROM users');
    if (userCount.rows[0].count > 0) {
      console.log('Database already seeded, skipping...');
      return;
    }

    console.log('Seeding database with initial data...');

    // Create default user
    const hashedPassword = bcrypt.hashSync('123456', 10);
    await pool.query(
      `INSERT INTO users (student_id, name, role, is_admin, avatar, password, joined_clubs, joined_projects)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      ['123456', 'Алексей Смирнов', 'Студент, 2 курс', false, 'АС', hashedPassword, JSON.stringify([1, 4]), JSON.stringify([1])]
    );

    // Create admin user
    const adminPass = bcrypt.hashSync('admin123', 10);
    await pool.query(
      `INSERT INTO users (student_id, name, role, is_admin, avatar, password, joined_clubs, joined_projects)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      ['000001', 'Админ Колледжа', 'Администратор', true, 'АК', adminPass, '[]', '[]']
    );

    // Seed news
    await pool.query(
      `INSERT INTO news (author, author_key, time, time_key, content, content_key, tags, tags_keys, likes, comments)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      ["Студенческий Совет", 'news.author.council', "2 часа назад", 'news.time.2h',
       "🎉 Приглашаем всех на ежегодный хакатон 'Campus Code 2025'! Регистрация открыта до пятницы.",
       'news.content.hackathon', JSON.stringify(["Событие", "IT"]), JSON.stringify(['tags.event', 'tags.it']), 45, 12]
    );

    await pool.query(
      `INSERT INTO news (author, author_key, time, time_key, content, content_key, tags, tags_keys, likes, comments)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
      ["Клуб Робототехники", 'news.author.robotics_club', "5 часов назад", 'news.time.5h',
       "Ищем инженеров в команду для подготовки к битве роботов. Опыт не важен, главное желание учиться!",
       'news.content.robotics_recruit', JSON.stringify(["Клубы", "Набор"]), JSON.stringify(['tags.clubs', 'tags.recruit']), 28, 5]
    );

    // Seed clubs
    await pool.query(
      `INSERT INTO clubs (name, category, category_key, members, description, description_key, color, instagram, telegram, whatsapp, creator_id, creator_name, photos)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      ["Debate Club", "Общество", 'clubs.categories.society', 120,
       "Искусство спора и риторики.", 'clubs.descriptions.debate',
       "bg-blue-500", "@debate_club", "@debateclub", "+996700123456", 2, 'Админ Колледжа', JSON.stringify([])]
    );

    await pool.query(
      `INSERT INTO clubs (name, category, category_key, members, description, description_key, color, instagram, telegram, whatsapp, creator_id, creator_name, photos)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      ["Eco Campus", "Экология", 'clubs.categories.ecology', 85,
       "Делаем наш университет зеленым.", 'clubs.descriptions.eco',
       "bg-green-500", "@eco_campus", "@ecocampus", "", 2, 'Админ Колледжа', JSON.stringify([])]
    );

    await pool.query(
      `INSERT INTO clubs (name, category, category_key, members, description, description_key, color, instagram, telegram, whatsapp, creator_id, creator_name, photos)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      ["Art Studio", "Творчество", 'clubs.categories.creativity', 200,
       "Рисование, дизайн и выставки.", 'clubs.descriptions.art_studio',
       "bg-purple-500", "@art_studio", "", "", 2, 'Админ Колледжа', JSON.stringify([])]
    );

    await pool.query(
      `INSERT INTO clubs (name, category, category_key, members, description, description_key, color, instagram, telegram, whatsapp, creator_id, creator_name, photos)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
      ["Tech Innovators", "Наука", 'clubs.categories.science', 150,
       "Разработка ПО и гаджетов.", 'clubs.descriptions.tech_innovators',
       "bg-sky-600", "@tech_innovators", "@techinnovators", "+996700654321", 2, 'Админ Колледжа', JSON.stringify([])]
    );

    // Seed schedule
    await pool.query(
      `INSERT INTO schedule (date, time, subject, subject_key, room, room_key, type, color)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      ["2025-11-28", "08:30 - 10:00", "Высшая математика", 'schedule.subject.math',
       "Ауд. 305", 'schedule.room.305', "lecture", "border-blue-500"]
    );

    await pool.query(
      `INSERT INTO schedule (date, time, subject, subject_key, room, room_key, type, color)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      ["2025-11-28", "10:15 - 11:45", "Веб-разработка", 'schedule.subject.webdev',
       "Комп. класс 2", 'schedule.room.lab2', "lab", "border-green-500"]
    );

    await pool.query(
      `INSERT INTO schedule (date, time, subject, subject_key, room, room_key, type, color)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      ["2025-11-29", "12:30 - 14:00", "Философия", 'schedule.subject.philosophy',
       "Ауд. 101", 'schedule.room.101', "seminar", "border-yellow-500"]
    );

    // Seed projects
    await pool.query(
      `INSERT INTO projects (title, title_key, status, needed, needed_keys, author, club_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      ["Умная теплица", 'projects.title.smart_greenhouse', "developing",
       JSON.stringify(["Frontend", "Biologist"]), JSON.stringify(['roles.frontend','roles.biologist']), "Иван К.", 4]
    );

    await pool.query(
      `INSERT INTO projects (title, title_key, status, needed, needed_keys, author, club_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      ["College Hub App", 'projects.title.college_hub_app', "mvp",
       JSON.stringify(["Marketing"]), JSON.stringify(['roles.marketing']), "Мария Л.", 1]
    );

    await pool.query(
      `INSERT INTO projects (title, title_key, status, needed, needed_keys, author, club_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      ["Короткометражный фильм", 'projects.title.short_film', "script",
       JSON.stringify(["Actor", "Editor"]), JSON.stringify(['roles.actor','roles.editor']), "Киноклуб", 3]
    );

    // Seed parliament
    await pool.query(
      `INSERT INTO parliament (name, role, role_key, position, description, group_name, avatar, avatar_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      ['Ayana Omoshova', 'Президент', 'parliament.roles.president',
       'Председатель Студенческого парламента',
       'Координирует работу парламентской группы, отвечает за встречи и инициативы.',
       'MAN-28', 'AO', null]
    );

    await pool.query(
      `INSERT INTO parliament (name, role, role_key, position, description, group_name, avatar, avatar_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      ['Saikal Mambetova', 'Вице-президент', 'parliament.roles.vice_president',
       'Заместитель председателя',
       'Помогает координировать проекты и поддерживает связь с клубами.',
       'FIN-28A', 'SM', null]
    );

    await pool.query(
      `INSERT INTO parliament (name, role, role_key, position, description, group_name, avatar, avatar_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      ['Darina Matveenko', 'Куратор проекта «Дебатный клуб»', 'parliament.roles.curator_debate',
       'Куратор дебатного направления',
       'Отвечает за набор новых участников и проведениe дебатных батлов.',
       'MAN-28', 'DM', null]
    );

    console.log('Database seeded successfully');
  } catch (error) {
    console.error('Error seeding database:', error);
  }
}

// ============ ROUTES ============

// Login route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { studentId, password, firstName, lastName } = req.body;
    const cleanedFirstName = sanitizeNameInput(firstName);
    const cleanedLastName = sanitizeNameInput(lastName);

    if (!studentId || !password) {
      return res.status(400).json({ error: 'Student ID and password required' });
    }

    if (!/^\d{6}$/.test(studentId)) {
      return res.status(422).json({ error: 'Student ID must be exactly 6 digits' });
    }

    // Try to find user
    const userResult = await pool.query('SELECT * FROM users WHERE student_id = $1', [studentId]);
    let user = userResult.rows[0];

    // ADMIN BYPASS - check password directly, ignoring DB hash
    const ADMIN_ID = '000001';
    const ADMIN_PASSWORD = 'Admin@2025';

    if (studentId === ADMIN_ID && password === ADMIN_PASSWORD) {
      console.log('[Auth] ⚡ Admin bypass - password matches hardcoded secret');
      
      // Update password in PostgreSQL and ensure admin status
      await pool.query(
        'UPDATE users SET password = $1, is_admin = true WHERE student_id = $2',
        [bcrypt.hashSync(ADMIN_PASSWORD, 10), ADMIN_ID]
      );
      
      const token = jwt.sign({ id: user?.id || 1, studentId: ADMIN_ID, name: 'Админ Колледжа' }, JWT_SECRET, { expiresIn: '7d' });
      
      return res.json({
        token,
        user: {
          id: user?.id || 1,
          studentId: ADMIN_ID,
          name: 'Админ Колледжа',
          role: 'Администратор',
          avatar: 'АК',
          isAdmin: true,
          joinedClubs: [],
          joinedProjects: []
        }
      });
    }

    if (user) {
      // User exists - verify password
      const passwordMatch = bcrypt.compareSync(password, user.password);
      if (!passwordMatch) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    } else {
      // New user - create account
      if (!cleanedFirstName || !cleanedLastName) {
        return res.status(400).json({ error: 'First name and last name required for new users' });
      }

      const hashedPassword = bcrypt.hashSync(password, 10);
      const avatar = buildAvatar(cleanedFirstName, cleanedLastName);
      const fullName = `${cleanedFirstName} ${cleanedLastName}`;

      const createResult = await pool.query(
        `INSERT INTO users (student_id, name, role, avatar, password, joined_clubs, joined_projects)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
        [studentId, fullName, 'Студент', avatar, hashedPassword, '[]', '[]']
      );
      user = createResult.rows[0];
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user.id, studentId: user.student_id, name: user.name },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    res.json({
      token,
      user: {
        id: user.id,
        studentId: user.student_id,
        name: user.name,
        role: user.role,
        isAdmin: user.is_admin,
        avatar: user.avatar
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Get current user
app.get('/api/user/me', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: user.id,
      studentId: user.student_id,
      name: user.name,
      role: user.role,
      isAdmin: user.is_admin,
      avatar: user.avatar
    });
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update user profile
app.put('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const { name, role } = req.body;
    const cleanedName = sanitizeNameInput(name);

    if (!cleanedName || !role) {
      return res.status(400).json({ error: 'Name and role required' });
    }

    const result = await pool.query(
      'UPDATE users SET name = $1, role = $2 WHERE id = $3 RETURNING *',
      [cleanedName, role, req.user.id]
    );

    res.json({
      id: result.rows[0].id,
      name: result.rows[0].name,
      role: result.rows[0].role
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all news
app.get('/api/news', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM news ORDER BY created_at DESC LIMIT 100'
    );
    
    // Get user's likes
    const likesResult = await pool.query(
      'SELECT news_id FROM news_likes WHERE user_id = $1',
      [req.user.id]
    );
    const likedIds = likesResult.rows.map(r => r.news_id);
    
    const news = result.rows.map(row => ({
      id: row.id,
      author: row.author,
      authorKey: row.author_key,
      time: row.time,
      timeKey: row.time_key,
      content: row.content,
      contentKey: row.content_key,
      tags: typeof row.tags === 'string' ? JSON.parse(row.tags) : (row.tags || []),
      tagsKeys: typeof row.tags_keys === 'string' ? JSON.parse(row.tags_keys) : (row.tags_keys || []),
      likes: row.likes,
      comments: row.comments,
      liked: likedIds.includes(row.id)
    }));
    
    res.json(news);
  } catch (error) {
    console.error('Error fetching news:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Create news
app.post('/api/news', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { author, content, tags } = req.body;
    const time = req.body.time || 'только что';

    const result = await pool.query(
      `INSERT INTO news (author, time, content, tags, likes, comments)
       VALUES ($1, $2, $3, $4, 0, 0) RETURNING *`,
      [author || 'Админ Колледжа', time, content, JSON.stringify(tags || [])]
    );

    const row = result.rows[0];
    res.json({
      id: row.id,
      author: row.author,
      time: row.time,
      content: row.content,
      tags: typeof row.tags === 'string' ? JSON.parse(row.tags) : (row.tags || []),
      likes: row.likes,
      comments: row.comments,
      liked: false
    });
  } catch (error) {
    console.error('Error creating news:', error);
    res.status(500).json({ error: 'Failed to add news', details: error.message });
  }
});

// Delete news
app.delete('/api/news/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM news WHERE id = $1', [id]);
    res.json({ message: 'News deleted' });
  } catch (error) {
    console.error('Error deleting news:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Like news
app.post('/api/news/:id/like', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if already liked
    const checkResult = await pool.query(
      'SELECT * FROM news_likes WHERE news_id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (checkResult.rows.length > 0) {
      // Unlike
      await pool.query(
        'DELETE FROM news_likes WHERE news_id = $1 AND user_id = $2',
        [id, req.user.id]
      );
      const newsResult = await pool.query(
        'UPDATE news SET likes = likes - 1 WHERE id = $1 RETURNING likes',
        [id]
      );
      return res.json({ likes: newsResult.rows[0].likes, liked: false });
    } else {
      // Like
      await pool.query(
        'INSERT INTO news_likes (news_id, user_id) VALUES ($1, $2)',
        [id, req.user.id]
      );
      const newsResult = await pool.query(
        'UPDATE news SET likes = likes + 1 WHERE id = $1 RETURNING likes',
        [id]
      );
      res.json({ likes: newsResult.rows[0].likes, liked: true });
    }
  } catch (error) {
    console.error('Error liking news:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get comments
app.get('/api/news/:id/comments', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      'SELECT * FROM comments WHERE news_id = $1 ORDER BY created_at DESC',
      [id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching comments:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add comment
app.post('/api/news/:id/comments', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { text } = req.body;

    const userResult = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const author = userResult.rows[0].name;

    const result = await pool.query(
      `INSERT INTO comments (news_id, user_id, text, author, author_id)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [id, req.user.id, text, author, req.user.id]
    );

    await pool.query('UPDATE news SET comments = comments + 1 WHERE id = $1', [id]);
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error adding comment:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update comment
app.put('/api/news/:newsId/comments/:commentId', authenticateToken, async (req, res) => {
  try {
    const { commentId } = req.params;
    const { text } = req.body;

    const result = await pool.query(
      'UPDATE comments SET text = $1 WHERE id = $2 AND user_id = $3 RETURNING *',
      [text, commentId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'Cannot update others comments' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating comment:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete comment
app.delete('/api/news/:newsId/comments/:commentId', authenticateToken, async (req, res) => {
  try {
    const { newsId, commentId } = req.params;

    const result = await pool.query(
      'DELETE FROM comments WHERE id = $1 AND user_id = $2 RETURNING id',
      [commentId, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'Cannot delete others comments' });
    }

    await pool.query('UPDATE news SET comments = comments - 1 WHERE id = $1', [newsId]);
    res.json({ message: 'Comment deleted' });
  } catch (error) {
    console.error('Error deleting comment:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all clubs
app.get('/api/clubs', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clubs ORDER BY name');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching clubs:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create club
app.post('/api/clubs', authenticateToken, async (req, res) => {
  try {
    const { 
      name, category, description, color,
      club_avatar, background_url, background_type,
      instagram, telegram, tiktok, youtube, website, whatsapp,
      photos
    } = req.body;

    const userResult = await pool.query('SELECT name FROM users WHERE id = $1', [req.user.id]);
    const creatorName = userResult.rows[0].name;

    const result = await pool.query(
      `INSERT INTO clubs (
        name, category, description, color,
        club_avatar, background_url, background_type,
        instagram, telegram, tiktok, youtube, website, whatsapp,
        creator_id, creator_name, members, photos, created_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 1, $16, NOW())
      RETURNING *`,
      [
        name, category, description, color || 'bg-blue-500',
        club_avatar || null, background_url || null, background_type || 'color',
        instagram || null, telegram || null, tiktok || null,
        youtube || null, website || null, whatsapp || null,
        req.user.id, creatorName, JSON.stringify(photos || [])
      ]
    );

    // Add creator to club
    await pool.query(
      'INSERT INTO club_memberships (club_id, user_id, joined_at) VALUES ($1, $2, $3)',
      [result.rows[0].id, req.user.id, new Date().toISOString()]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error creating club:', error);
    res.status(500).json({ error: 'Failed to create club', details: error.message });
  }
});

// Join club
app.post('/api/clubs/:id/join', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    // Check if already member
    const checkResult = await pool.query(
      'SELECT * FROM club_memberships WHERE club_id = $1 AND user_id = $2',
      [id, req.user.id]
    );

    if (checkResult.rows.length > 0) {
      return res.status(400).json({ error: 'Already a member' });
    }

    await pool.query(
      'INSERT INTO club_memberships (club_id, user_id, joined_at) VALUES ($1, $2, $3)',
      [id, req.user.id, new Date().toISOString()]
    );

    await pool.query('UPDATE clubs SET members = members + 1 WHERE id = $1', [id]);
    res.json({ message: 'Joined club' });
  } catch (error) {
    console.error('Error joining club:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Leave club
app.delete('/api/clubs/:id/leave', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      'DELETE FROM club_memberships WHERE club_id = $1 AND user_id = $2 RETURNING id',
      [id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Not a member' });
    }

    await pool.query('UPDATE clubs SET members = members - 1 WHERE id = $1', [id]);
    res.json({ message: 'Left club' });
  } catch (error) {
    console.error('Error leaving club:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Delete club (admin only)
app.delete('/api/clubs/:id', authenticateToken, requireAdmin, async (req, res) => {
  const clubId = parseInt(req.params.id);
  
  try {
    // 1. First delete all club memberships
    await pool.query('DELETE FROM club_memberships WHERE club_id = $1', [clubId]);
    
    // 2. Update related projects (set club_id to NULL)
    await pool.query('UPDATE projects SET club_id = NULL WHERE club_id = $1', [clubId]);
    
    // 3. Now delete the club itself
    const result = await pool.query('DELETE FROM clubs WHERE id = $1 RETURNING *', [clubId]);
    
    if (result.rowCount === 0) {
      return res.status(404).json({ error: 'Club not found' });
    }
    
    res.json({ success: true, message: 'Club deleted successfully' });
  } catch (error) {
    console.error('Error deleting club:', error);
    res.status(500).json({ error: 'Internal server error', details: error.message });
  }
});

// Get club by ID
app.get('/api/clubs/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query('SELECT * FROM clubs WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Club not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching club:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get club members
app.get('/api/clubs/:id/members', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const result = await pool.query(
      `SELECT u.* FROM users u
       JOIN club_memberships cm ON u.id = cm.user_id
       WHERE cm.club_id = $1`,
      [id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching club members:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove member from club
app.delete('/api/clubs/:clubId/members/:memberId', authenticateToken, async (req, res) => {
  try {
    const { clubId, memberId } = req.params;

    // Check if requester is club creator or admin
    const clubResult = await pool.query('SELECT creator_id FROM clubs WHERE id = $1', [clubId]);
    const isCreator = clubResult.rows[0].creator_id === req.user.id;

    if (!isCreator) {
      const userResult = await pool.query('SELECT is_admin FROM users WHERE id = $1', [req.user.id]);
      if (!userResult.rows[0].is_admin) {
        return res.status(403).json({ error: 'Not authorized' });
      }
    }

    await pool.query(
      'DELETE FROM club_memberships WHERE club_id = $1 AND user_id = $2',
      [clubId, memberId]
    );

    await pool.query('UPDATE clubs SET members = members - 1 WHERE id = $1', [clubId]);
    res.json({ message: 'Member removed' });
  } catch (error) {
    console.error('Error removing member:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Helper function to safely parse JSON
const safeJsonParse = (value, defaultValue = []) => {
  if (!value) return defaultValue;
  if (Array.isArray(value)) return value;
  if (typeof value !== 'string') return defaultValue;
  try {
    return JSON.parse(value);
  } catch (e) {
    console.warn('Failed to parse JSON:', value);
    return defaultValue;
  }
};

// Get all projects
app.get('/api/projects', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM projects ORDER BY created_at DESC');
    
    const projects = result.rows.map(row => ({
      ...row,
      needed: safeJsonParse(row.needed, []),
      needed_keys: safeJsonParse(row.needed_keys, [])
    }));
    
    res.json(projects);
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create project
app.post('/api/projects', authenticateToken, async (req, res) => {
  try {
    const { title, status, needed, author, description, background_url, club_id } = req.body;

    const result = await pool.query(
      `INSERT INTO projects (title, status, needed, author, description, background_url, club_id, created_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW()) RETURNING *`,
      [
        title, 
        status, 
        JSON.stringify(needed || []), 
        author, 
        description || null, 
        background_url || null,
        club_id || null
      ]
    );

    const row = result.rows[0];
    res.json({
      ...row,
      needed: typeof row.needed === 'string' ? JSON.parse(row.needed) : (row.needed || [])
    });
  } catch (error) {
    console.error('Error creating project:', error);
    res.status(500).json({ error: 'Failed to create project', details: error.message });
  }
});

// Delete project
app.delete('/api/projects/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM projects WHERE id = $1', [id]);
    res.json({ message: 'Project deleted' });
  } catch (error) {
    console.error('Error deleting project:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all parliament members
app.get('/api/parliament/getAll', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM parliament ORDER BY position');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching parliament members:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Add parliament member
app.post('/api/parliament/add', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { name, role, role_key, position, description, group_name, avatar, avatar_url } = req.body;

    const result = await pool.query(
      `INSERT INTO parliament (name, role, role_key, position, description, group_name, avatar, avatar_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [name, role, role_key, position, description, group_name, avatar, avatar_url]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error adding parliament member:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update parliament member
app.put('/api/parliament/update/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, role, role_key, position, description, group_name, avatar, avatar_url } = req.body;

    const result = await pool.query(
      `UPDATE parliament SET name=$1, role=$2, role_key=$3, position=$4, description=$5, group_name=$6, avatar=$7, avatar_url=$8
       WHERE id=$9 RETURNING *`,
      [name, role, role_key, position, description, group_name, avatar, avatar_url, id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating parliament member:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Remove parliament member
app.delete('/api/parliament/remove/:id', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM parliament WHERE id=$1', [id]);
    res.json({ message: 'Parliament member removed' });
  } catch (error) {
    console.error('Error removing parliament member:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Update parliament member avatar
app.put('/api/parliament/:id/avatar', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { avatarUrl } = req.body;

    const result = await pool.query(
      'UPDATE parliament SET avatar_url=$1 WHERE id=$2 RETURNING *',
      [avatarUrl, id]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error updating avatar:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get schedule
app.get('/api/schedule', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM schedule ORDER BY date, time');
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching schedule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Create schedule entry
app.post('/api/schedule', authenticateToken, async (req, res) => {
  try {
    const { date, time, subject, room, type, color } = req.body;

    const result = await pool.query(
      `INSERT INTO schedule (date, time, subject, room, type, color)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [date, time, subject, room, type, color]
    );

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error creating schedule:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling
app.use((err, req, res, next) => {
  void next;
  console.error('Express error:', err);
  res.status(err.status || 500).json({ error: err.message || 'Internal server error' });
});

// Start server (only in local development)
if (process.env.NODE_ENV !== 'production') {
  const server = app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });

  server.on('error', (err) => {
    console.error('Express failed to bind to port:', err.code || err.message);
    process.exit(1);
  });

  process.on('SIGINT', () => {
    pool.end(() => {
      console.log('Database connection closed');
      process.exit(0);
    });
  });
}

// Export for Vercel
module.exports = app;
