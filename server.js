require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Email configuration using Gmail with app password
// Note: Use environment variables in production
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

  // Don't verify - just try to send and handle errors
  console.log('Email transporter configured (credentials will be validated on first use)');
} else {
  // Use Ethereal for testing - automatically creates test account
  nodemailer.createTestAccount((err, testAccount) => {
    if (err) {
      console.log('Could not create Ethereal test account:', err.message);
      console.log('Email will be logged to console only.');
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

// Global error handlers
process.on('uncaughtException', (err) => {
  console.error('UNCAUGHT EXCEPTION:', err);
  process.exit(1);
});

process.on('unhandledRejection', (reason) => {
  console.error('UNHANDLED REJECTION:', reason);
});

// Middleware
// Explicit CORS configuration to allow Vite dev server origin and headers
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
    return callback(null, true);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
// Handle preflight
app.options('*', cors());
const jsonLimit = process.env.JSON_LIMIT || '2mb';
app.use(express.json({ limit: jsonLimit }));
app.use(express.urlencoded({ extended: true, limit: jsonLimit }));

// Database connection
const db = new sqlite3.Database(path.join(__dirname, 'database.sqlite'), (err) => {
  if (err) {
    console.error('Database connection error:', err.message);
    console.error('Make sure the SQLite file exists and permissions allow read/write access.');
    process.exit(1);
  }
  console.log('Connected to SQLite database');
  initializeDatabase();
});

db.on('error', (err) => {
  console.error('Database error event:', err);
});

db.on('trace', (sql) => {
  if (sql.includes('SELECT') || sql.includes('UPDATE')) {
    console.log('SQL trace:', sql.substring(0, 100));
  }
});

const ensureColumnExists = (table, column, definition) => {
  db.all(`PRAGMA table_info(${table})`, (err, rows) => {
    if (err) {
      console.error(`Unable to read schema for ${table}:`, err);
      return;
    }
    const exists = rows.some(row => row.name === column);
    if (!exists) {
      db.run(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`,
        (alterErr) => {
          if (alterErr) {
            console.error(`Failed to add column ${column} to ${table}:`, alterErr);
          } else {
            console.log(`Added missing column ${column} to ${table}`);
          }
        });
    }
  });
};

const ensureClubMembershipsTable = () => {
  db.run(`CREATE TABLE IF NOT EXISTS club_memberships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    clubId INTEGER NOT NULL,
    userId INTEGER NOT NULL,
    joinedAt TEXT NOT NULL,
    FOREIGN KEY (clubId) REFERENCES clubs(id),
    FOREIGN KEY (userId) REFERENCES users(id),
    UNIQUE(clubId, userId)
  )`);
};

const syncClubMembershipsFromUsers = () => {
  db.get('SELECT COUNT(*) as count FROM club_memberships', (err, row) => {
    if (err) {
      console.error('Failed to inspect club_memberships:', err);
      return;
    }
    if (row && row.count > 0) return;
    db.each('SELECT id, joinedClubs FROM users', (userErr, user) => {
      if (userErr || !user) return;
      let joinedClubs = [];
      try {
        joinedClubs = JSON.parse(user.joinedClubs || '[]');
      } catch (parseErr) {
        console.error('Failed to parse joinedClubs for user', user.id, parseErr);
        joinedClubs = [];
      }
      const now = new Date().toISOString();
      joinedClubs.forEach((clubId) => {
        const parsedId = parseInt(clubId);
        if (!isNaN(parsedId)) {
          db.run(`INSERT OR IGNORE INTO club_memberships (clubId, userId, joinedAt)
                  VALUES (?, ?, ?)`,
            [parsedId, user.id, now]);
        }
      });
    });
  });
};

// Authentication middleware
const authenticateToken = (req, res, next) => {
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

// Admin-only middleware
const requireAdmin = (req, res, next) => {
  db.get('SELECT isAdmin FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(403).json({ error: 'Forbidden' });
    if (user.isAdmin !== 1) return res.status(403).json({ error: 'Admin rights required' });
    next();
  });
};

// Initialize database schema
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      studentId TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      role TEXT,
      isAdmin INTEGER DEFAULT 0,
      avatar TEXT,
      password TEXT NOT NULL,
      joinedClubs TEXT DEFAULT '[]',
      joinedProjects TEXT DEFAULT '[]',
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // News table
    db.run(`CREATE TABLE IF NOT EXISTS news (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      author TEXT NOT NULL,
      authorKey TEXT,
      time TEXT NOT NULL,
      timeKey TEXT,
      content TEXT NOT NULL,
      contentKey TEXT,
      tags TEXT,
      tagsKeys TEXT,
      likes INTEGER DEFAULT 0,
      comments INTEGER DEFAULT 0,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // News likes table
    db.run(`CREATE TABLE IF NOT EXISTS news_likes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      newsId INTEGER NOT NULL,
      userId INTEGER NOT NULL,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (newsId) REFERENCES news(id),
      FOREIGN KEY (userId) REFERENCES users(id),
      UNIQUE(newsId, userId)
    )`);

    // Comments table
    db.run(`CREATE TABLE IF NOT EXISTS comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      newsId INTEGER NOT NULL,
      userId INTEGER NOT NULL,
      text TEXT NOT NULL,
      author TEXT NOT NULL,
      authorId TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (newsId) REFERENCES news(id),
      FOREIGN KEY (userId) REFERENCES users(id)
    )`);

    // Clubs table
    db.run(`CREATE TABLE IF NOT EXISTS clubs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      category TEXT NOT NULL,
      categoryKey TEXT,
      members INTEGER DEFAULT 0,
      description TEXT,
      descriptionKey TEXT,
      color TEXT DEFAULT 'bg-blue-500',
      instagram TEXT,
      telegram TEXT,
      whatsapp TEXT,
      tiktok TEXT,
      youtube TEXT,
      website TEXT,
      creatorId INTEGER,
      creatorName TEXT,
      photos TEXT DEFAULT '[]',
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Projects table
    db.run(`CREATE TABLE IF NOT EXISTS projects (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      titleKey TEXT,
      status TEXT NOT NULL,
      needed TEXT,
      neededKeys TEXT,
      author TEXT NOT NULL,
      clubId INTEGER,
      backgroundUrl TEXT,
      description TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
      if (err) console.error('Error creating projects table:', err);
      // Ensure description column exists for old databases
      ensureColumnExists('projects', 'description', 'TEXT');
    });

    // Schedule table
    db.run(`CREATE TABLE IF NOT EXISTS schedule (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      date TEXT NOT NULL,
      time TEXT NOT NULL,
      subject TEXT NOT NULL,
      subjectKey TEXT,
      room TEXT NOT NULL,
      roomKey TEXT,
      type TEXT,
      color TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    // Activities table
    db.run(`CREATE TABLE IF NOT EXISTS activities (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      club TEXT NOT NULL,
      action TEXT NOT NULL,
      actionKey TEXT,
      detail TEXT NOT NULL,
      detailKey TEXT,
      date TEXT NOT NULL,
      dateKey TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (userId) REFERENCES users(id)
    )`);

    // Parliament table
    db.run(`CREATE TABLE IF NOT EXISTS parliament (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      role TEXT NOT NULL,
      roleKey TEXT,
      position TEXT,
      description TEXT,
      groupName TEXT,
      avatar TEXT,
      avatarUrl TEXT,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    console.log('Database schema initialized');
    seedDatabase();
    ensureColumnExists('clubs', 'creatorId', 'INTEGER DEFAULT NULL');
    ensureColumnExists('clubs', 'creatorName', 'TEXT');
    ensureColumnExists('clubs', 'photos', "TEXT DEFAULT '[]'");
    ensureColumnExists('clubs', 'tiktok', 'TEXT');
    ensureColumnExists('clubs', 'youtube', 'TEXT');
    ensureColumnExists('clubs', 'website', 'TEXT');
    ensureColumnExists('clubs', 'backgroundUrl', 'TEXT');
    ensureColumnExists('clubs', 'backgroundType', "TEXT DEFAULT 'color'");
    ensureColumnExists('clubs', 'clubAvatar', 'TEXT');
    ensureColumnExists('projects', 'clubId', 'INTEGER');
    ensureColumnExists('projects', 'backgroundUrl', 'TEXT');
    ensureColumnExists('projects', 'description', 'TEXT');
    ensureColumnExists('parliament', 'position', 'TEXT');
    ensureColumnExists('parliament', 'description', 'TEXT');
    ensureColumnExists('parliament', 'avatarUrl', 'TEXT');
    ensureClubMembershipsTable();
    syncClubMembershipsFromUsers();
  });
}

// Seed initial data
function seedDatabase() {
  console.log('Starting seedDatabase...');
  db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
    if (err) {
      console.error('Error checking users:', err);
      return;
    }
    if (row && row.count > 0) {
      console.log('Database already seeded, skipping...');
      return;
    }
    
    console.log('Seeding database with initial data...');
    
    // Create default user (6-digit studentId)
    const hashedPassword = bcrypt.hashSync('123456', 10);
    db.run(`INSERT INTO users (studentId, name, role, isAdmin, avatar, password, joinedClubs, joinedProjects) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ['123456', 'Алексей Смирнов', 'Студент, 2 курс', 0, 'АС', hashedPassword, JSON.stringify([1, 4]), JSON.stringify([1])],
      (err) => { if (err) console.error('Error inserting user 1:', err); });

    // Create admin user (6-digit studentId)
    const adminPass = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT INTO users (studentId, name, role, isAdmin, avatar, password, joinedClubs, joinedProjects)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ['000001', 'Админ Колледжа', 'Администратор', 1, 'АК', adminPass, '[]', '[]'],
      (err) => { if (err) console.error('Error inserting user 2:', err); });

    // Seed news
    db.run(`INSERT INTO news (author, authorKey, time, timeKey, content, contentKey, tags, tagsKeys, likes, comments)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ["Студенческий Совет", 'news.author.council', "2 часа назад", 'news.time.2h', 
       "🎉 Приглашаем всех на ежегодный хакатон 'Campus Code 2025'! Регистрация открыта до пятницы.",
       'news.content.hackathon', JSON.stringify(["Событие", "IT"]), JSON.stringify(['tags.event', 'tags.it']), 45, 12],
      (err) => { if (err) console.error('Error inserting news 1:', err); });

    db.run(`INSERT INTO news (author, authorKey, time, timeKey, content, contentKey, tags, tagsKeys, likes, comments)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ["Клуб Робототехники", 'news.author.robotics_club', "5 часов назад", 'news.time.5h',
       "Ищем инженеров в команду для подготовки к битве роботов. Опыт не важен, главное желание учиться!",
       'news.content.robotics_recruit', JSON.stringify(["Клубы", "Набор"]), JSON.stringify(['tags.clubs', 'tags.recruit']), 28, 5],
      (err) => { if (err) console.error('Error inserting news 2:', err); });

    // Seed clubs
        db.run(`INSERT INTO clubs (name, category, categoryKey, members, description, descriptionKey, color, instagram, telegram, whatsapp, creatorId, creatorName, photos)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ["Debate Club", "Общество", 'clubs.categories.society', 120, 
       "Искусство спора и риторики.", 'clubs.descriptions.debate',
       "bg-blue-500", "@debate_club", "@debateclub", "+996700123456", 2, 'Админ Колледжа', JSON.stringify([])],
      (err) => { if (err) console.error('Error inserting club 1:', err); });

        db.run(`INSERT INTO clubs (name, category, categoryKey, members, description, descriptionKey, color, instagram, telegram, whatsapp, creatorId, creatorName, photos)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ["Eco Campus", "Экология", 'clubs.categories.ecology', 85,
       "Делаем наш университет зеленым.", 'clubs.descriptions.eco',
       "bg-green-500", "@eco_campus", "@ecocampus", "", 2, 'Админ Колледжа', JSON.stringify([])],
      (err) => { if (err) console.error('Error inserting club 2:', err); });

        db.run(`INSERT INTO clubs (name, category, categoryKey, members, description, descriptionKey, color, instagram, telegram, whatsapp, creatorId, creatorName, photos)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ["Art Studio", "Творчество", 'clubs.categories.creativity', 200,
       "Рисование, дизайн и выставки.", 'clubs.descriptions.art_studio',
       "bg-purple-500", "@art_studio", "", "", 2, 'Админ Колледжа', JSON.stringify([])],
      (err) => { if (err) console.error('Error inserting club 3:', err); });

        db.run(`INSERT INTO clubs (name, category, categoryKey, members, description, descriptionKey, color, instagram, telegram, whatsapp, creatorId, creatorName, photos)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ["Tech Innovators", "Наука", 'clubs.categories.science', 150,
       "Разработка ПО и гаджетов.", 'clubs.descriptions.tech_innovators',
       "bg-sky-600", "@tech_innovators", "@techinnovators", "+996700654321", 2, 'Админ Колледжа', JSON.stringify([])],
      (err) => { if (err) console.error('Error inserting club 4:', err); });

    // Seed schedule
    db.run(`INSERT INTO schedule (date, time, subject, subjectKey, room, roomKey, type, color)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ["2025-11-28", "08:30 - 10:00", "Высшая математика", 'schedule.subject.math',
       "Ауд. 305", 'schedule.room.305', "lecture", "border-blue-500"],
      (err) => { if (err) console.error('Error inserting schedule 1:', err); });

    db.run(`INSERT INTO schedule (date, time, subject, subjectKey, room, roomKey, type, color)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ["2025-11-28", "10:15 - 11:45", "Веб-разработка", 'schedule.subject.webdev',
       "Комп. класс 2", 'schedule.room.lab2', "lab", "border-green-500"],
      (err) => { if (err) console.error('Error inserting schedule 2:', err); });

    db.run(`INSERT INTO schedule (date, time, subject, subjectKey, room, roomKey, type, color)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      ["2025-11-29", "12:30 - 14:00", "Философия", 'schedule.subject.philosophy',
       "Ауд. 101", 'schedule.room.101', "seminar", "border-yellow-500"],
      (err) => { if (err) console.error('Error inserting schedule 3:', err); });

    // Seed projects
        db.run(`INSERT INTO projects (title, titleKey, status, needed, neededKeys, author, clubId)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ["Умная теплица", 'projects.title.smart_greenhouse', "developing",
       JSON.stringify(["Frontend", "Biologist"]), JSON.stringify(['roles.frontend','roles.biologist']), "Иван К.", 4],
      (err) => { if (err) console.error('Error inserting project 1:', err); });

        db.run(`INSERT INTO projects (title, titleKey, status, needed, neededKeys, author, clubId)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ["College Hub App", 'projects.title.college_hub_app', "mvp",
       JSON.stringify(["Marketing"]), JSON.stringify(['roles.marketing']), "Мария Л.", 1],
      (err) => { if (err) console.error('Error inserting project 2:', err); });

        db.run(`INSERT INTO projects (title, titleKey, status, needed, neededKeys, author, clubId)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ["Короткометражный фильм", 'projects.title.short_film', "script",
       JSON.stringify(["Actor", "Editor"]), JSON.stringify(['roles.actor','roles.editor']), "Киноклуб", 3],
      (err) => { if (err) console.error('Error inserting project 3:', err); });

    // Seed parliament
    db.run(`INSERT INTO parliament (name, role, roleKey, position, description, groupName, avatar, avatarUrl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        'Ayana Omoshova',
        'Президент',
        'parliament.roles.president',
        'Председатель Студенческого парламента',
        'Координирует работу парламентской группы, отвечает за встречи и инициативы.',
        'MAN-28',
        'AO',
        null
      ],
      (err) => { if (err) console.error('Error inserting parliament 1:', err); });

    db.run(`INSERT INTO parliament (name, role, roleKey, position, description, groupName, avatar, avatarUrl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        'Saikal Mambetova',
        'Вице-президент',
        'parliament.roles.vice_president',
        'Заместитель председателя',
        'Помогает координировать проекты и поддерживает связь с клубами.',
        'FIN-28A',
        'SM',
        null
      ],
      (err) => { if (err) console.error('Error inserting parliament 2:', err); });

    db.run(`INSERT INTO parliament (name, role, roleKey, position, description, groupName, avatar, avatarUrl)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        'Darina Matveenko',
        'Куратор проекта «Дебатный клуб»',
        'parliament.roles.curator_debate',
        'Куратор дебатного направления',
        'Отвечает за набор новых участников и проведениe дебатных батлов.',
        'MAN-28',
        'DM',
        null
      ], 
      (err) => {
        if (err) {
          console.error('Error seeding database:', err);
        } else {
          console.log('Database seeded successfully');
        }
      });
  });
}

// ============= AUTH ROUTES =============

const sanitizeNameInput = (value) => (typeof value === 'string' ? value.trim() : '');
const buildDisplayName = (first, last) => (first && last ? `${first} ${last}` : 'Студент');
const buildAvatar = (first, last) => {
  const firstInitial = first?.[0] || 'С';
  const lastInitial = last?.[0] || 'Т';
  return `${firstInitial}${lastInitial}`.toUpperCase();
};

// Config endpoint - returns API URL for frontend
app.get('/api/config', (req, res) => {
  const apiUrl = process.env.API_URL || `http://localhost:${PORT}`;
  res.json({ apiUrl });
});

// Login
app.post('/api/auth/login', (req, res) => {
  try {
    const { studentId, password, firstName, lastName } = req.body;

    const cleanedFirstName = sanitizeNameInput(firstName);
    const cleanedLastName = sanitizeNameInput(lastName);

    if (!studentId || !password) {
      return res.status(400).json({ error: 'Student ID and password required' });
    }

    // Validate studentId (exactly 6 digits)
    if (!/^\d{6}$/.test(studentId)) {
      return res.status(422).json({ error: 'Student ID must be exactly 6 digits' });
    }

    db.get('SELECT * FROM users WHERE studentId = ?', [studentId], (err, user) => {
      try {
        if (err) {
          return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
          // Create new user if doesn't exist
          const hashedPassword = bcrypt.hashSync(password, 10);
          const name = buildDisplayName(cleanedFirstName, cleanedLastName);
          const avatar = buildAvatar(cleanedFirstName, cleanedLastName);

          db.run(`INSERT INTO users (studentId, name, role, avatar, password, joinedClubs, joinedProjects)
                  VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [studentId, name, 'Студент, 2 курс', avatar, hashedPassword, '[]', '[]'],
            function(err) {
              try {
                if (err) {
                  return res.status(500).json({ error: 'Failed to create user' });
                }

                const token = jwt.sign({ id: this.lastID, studentId }, JWT_SECRET, { expiresIn: '7d' });
                res.json({
                  token,
                  user: {
                    id: this.lastID,
                    studentId,
                    name,
                    role: 'Студент, 2 курс',
                    avatar,
                    joinedClubs: [],
                    joinedProjects: []
                  }
                });
              } catch (e) {
                console.error('Error in db.run callback:', e);
                res.status(500).json({ error: 'Internal server error' });
              }
            });
        } else {
          // Verify password
          if (!bcrypt.compareSync(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
          }

          const token = jwt.sign({ id: user.id, studentId: user.studentId }, JWT_SECRET, { expiresIn: '7d' });
          res.json({
            token,
            user: {
              id: user.id,
              studentId: user.studentId,
              name: user.name,
              role: user.role,
              avatar: user.avatar,
              isAdmin: user.isAdmin === 1,
              joinedClubs: JSON.parse(user.joinedClubs || '[]'),
              joinedProjects: JSON.parse(user.joinedProjects || '[]')
            }
          });
        }
      } catch (e) {
        console.error('Error in db.get callback:', e);
        res.status(500).json({ error: 'Internal server error' });
      }
    });
  } catch (error) {
    console.error('Error in login endpoint:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get current user
app.get('/api/user/me', authenticateToken, (req, res) => {
  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({
      id: user.id,
      studentId: user.studentId,
      name: user.name,
      role: user.role,
      avatar: user.avatar,
      isAdmin: user.isAdmin === 1,
      joinedClubs: JSON.parse(user.joinedClubs || '[]'),
      joinedProjects: JSON.parse(user.joinedProjects || '[]')
    });
  });
});

// Update user profile
app.put('/api/user/profile', authenticateToken, (req, res) => {
  const { name, role } = req.body;
  const avatar = name ? `${name.split(' ')[0][0]}${name.split(' ')[1]?.[0] || 'S'}`.toUpperCase() : null;

  db.run(`UPDATE users SET name = COALESCE(?, name), role = COALESCE(?, role), avatar = COALESCE(?, avatar)
          WHERE id = ?`,
    [name, role, avatar, req.user.id],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update profile' });
      }

      db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, user) => {
        res.json({
          id: user.id,
          studentId: user.studentId,
          name: user.name,
          role: user.role,
          avatar: user.avatar,
          joinedClubs: JSON.parse(user.joinedClubs || '[]'),
          joinedProjects: JSON.parse(user.joinedProjects || '[]')
        });
      });
    });
});

// ============= NEWS ROUTES =============

// Get all news
app.get('/api/news', authenticateToken, (req, res) => {
  db.all('SELECT * FROM news ORDER BY createdAt DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch news' });
    }

    // Get user's likes
    db.all('SELECT newsId FROM news_likes WHERE userId = ?', [req.user.id], (err, likes) => {
      const likedIds = likes ? likes.map(l => l.newsId) : [];
      
      const news = rows.map(row => ({
        id: row.id,
        author: row.author,
        authorKey: row.authorKey,
        time: row.time,
        timeKey: row.timeKey,
        content: row.content,
        contentKey: row.contentKey,
        tags: JSON.parse(row.tags || '[]'),
        tagsKeys: JSON.parse(row.tagsKeys || '[]'),
        likes: row.likes,
        comments: row.comments,
        liked: likedIds.includes(row.id)
      }));

      res.json(news);
    });
  });
});

// Admin: create news
app.post('/api/news', authenticateToken, requireAdmin, (req, res) => {
  const { author, content, tags } = req.body;
  const time = 'только что';
  db.run(`INSERT INTO news (author, time, content, tags, likes, comments)
          VALUES (?, ?, ?, ?, 0, 0)`,
    [author || 'Админ Колледжа', time, content, JSON.stringify(tags || [])],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to add news' });
      db.get('SELECT * FROM news WHERE id = ?', [this.lastID], (err, row) => {
        if (err || !row) return res.status(500).json({ error: 'Failed to fetch created news' });
        res.json({
          id: row.id,
          author: row.author,
          time: row.time,
          content: row.content,
          tags: JSON.parse(row.tags || '[]'),
          likes: row.likes,
          comments: row.comments,
          liked: false
        });
      });
    }
  );
});

// Admin: delete news
app.delete('/api/news/:id', authenticateToken, requireAdmin, (req, res) => {
  const newsId = parseInt(req.params.id);
  
  // Delete all comments for this news
  db.run('DELETE FROM comments WHERE newsId = ?', [newsId], (err) => {
    if (err) console.error('Failed to delete comments:', err);
    
    // Delete all likes for this news
    db.run('DELETE FROM news_likes WHERE newsId = ?', [newsId], (err) => {
      if (err) console.error('Failed to delete likes:', err);
      
      // Delete the news itself
      db.run('DELETE FROM news WHERE id = ?', [newsId], function(err) {
        if (err) return res.status(500).json({ error: 'Failed to delete news' });
        if (this.changes === 0) return res.status(404).json({ error: 'News not found' });
        res.json({ success: true });
      });
    });
  });
});

// Like/unlike news
app.post('/api/news/:id/like', authenticateToken, (req, res) => {
  const newsId = parseInt(req.params.id);

  db.get('SELECT * FROM news_likes WHERE newsId = ? AND userId = ?', [newsId, req.user.id], (err, like) => {
    if (like) {
      // Unlike
      db.run('DELETE FROM news_likes WHERE newsId = ? AND userId = ?', [newsId, req.user.id], (err) => {
        if (err) return res.status(500).json({ error: 'Failed to unlike' });
        
        db.run('UPDATE news SET likes = likes - 1 WHERE id = ?', [newsId], (err) => {
          if (err) return res.status(500).json({ error: 'Failed to update likes' });
          
          db.get('SELECT * FROM news WHERE id = ?', [newsId], (err, news) => {
            res.json({ ...news, liked: false, tags: JSON.parse(news.tags || '[]'), tagsKeys: JSON.parse(news.tagsKeys || '[]') });
          });
        });
      });
    } else {
      // Like
      db.run('INSERT INTO news_likes (newsId, userId) VALUES (?, ?)', [newsId, req.user.id], (err) => {
        if (err) return res.status(500).json({ error: 'Failed to like' });
        
        db.run('UPDATE news SET likes = likes + 1 WHERE id = ?', [newsId], (err) => {
          if (err) return res.status(500).json({ error: 'Failed to update likes' });
          
          db.get('SELECT * FROM news WHERE id = ?', [newsId], (err, news) => {
            res.json({ ...news, liked: true, tags: JSON.parse(news.tags || '[]'), tagsKeys: JSON.parse(news.tagsKeys || '[]') });
          });
        });
      });
    }
  });
});

// Get comments for news
app.get('/api/news/:id/comments', authenticateToken, (req, res) => {
  const newsId = parseInt(req.params.id);
  
  db.all('SELECT * FROM comments WHERE newsId = ? ORDER BY createdAt ASC', [newsId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch comments' });
    }
    res.json(rows);
  });
});

// Add comment
app.post('/api/news/:id/comments', authenticateToken, (req, res) => {
  const newsId = parseInt(req.params.id);
  const { text } = req.body;

  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User not found' });

    db.run(`INSERT INTO comments (newsId, userId, text, author, authorId)
            VALUES (?, ?, ?, ?, ?)`,
      [newsId, req.user.id, text, user.name, user.studentId],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to add comment' });

        db.run('UPDATE news SET comments = comments + 1 WHERE id = ?', [newsId]);

        res.json({
          id: this.lastID,
          newsId,
          text,
          author: user.name,
          authorId: user.studentId,
          createdAt: new Date().toISOString()
        });
      });
  });
});

// Update comment
app.put('/api/news/:newsId/comments/:commentId', authenticateToken, (req, res) => {
  const { commentId } = req.params;
  const { text } = req.body;

  db.run('UPDATE comments SET text = ? WHERE id = ? AND userId = ?',
    [text, commentId, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update comment' });
      if (this.changes === 0) return res.status(404).json({ error: 'Comment not found or unauthorized' });

      db.get('SELECT * FROM comments WHERE id = ?', [commentId], (err, comment) => {
        res.json(comment);
      });
    });
});

// Delete comment
app.delete('/api/news/:newsId/comments/:commentId', authenticateToken, (req, res) => {
  const { newsId, commentId } = req.params;

  // Check if user is admin
  db.get('SELECT isAdmin FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    
    const isAdmin = user && user.isAdmin === 1;
    const deleteQuery = isAdmin 
      ? 'DELETE FROM comments WHERE id = ?'
      : 'DELETE FROM comments WHERE id = ? AND userId = ?';
    const params = isAdmin ? [commentId] : [commentId, req.user.id];

    db.run(deleteQuery, params, function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete comment' });
      if (this.changes === 0) return res.status(404).json({ error: 'Comment not found or unauthorized' });

      db.run('UPDATE news SET comments = comments - 1 WHERE id = ?', [newsId]);
      res.json({ success: true });
    });
  });
});

// ============= CLUBS ROUTES =============

// Get all clubs
app.get('/api/clubs', authenticateToken, (req, res) => {
  db.all('SELECT * FROM clubs ORDER BY members DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch clubs' });
    }
    res.json(rows);
  });
});

// Create club
app.post('/api/clubs', authenticateToken, (req, res) => {
  const {
    name,
    category,
    description,
    color,
    instagram,
    telegram,
    whatsapp,
    tiktok,
    youtube,
    website,
    photos,
    backgroundUrl,
    backgroundType,
    clubAvatar
  } = req.body;
  const creatorId = req.user.id;
  const creatorName = req.user?.name || 'Админ';
  const photoList = JSON.stringify(Array.isArray(photos) ? photos : []);
  const finalBackgroundType = backgroundType || (backgroundUrl ? 'image' : 'color');
  const payload = {
    name,
    category,
    description,
    color: color || 'bg-blue-500',
    instagram: instagram || '',
    telegram: telegram || '',
    whatsapp: whatsapp || '',
    tiktok: tiktok || '',
    youtube: youtube || '',
    website: website || '',
    creatorId,
    creatorName,
    photos: photoList,
    backgroundUrl: backgroundUrl || '',
    backgroundType: finalBackgroundType,
    clubAvatar: clubAvatar || ''
  };
  const requiredFields = ['name', 'category', 'description'];
  const missingFields = requiredFields.filter((field) => !payload[field]?.trim());
  if (missingFields.length > 0) {
    console.warn('Club creation missing fields:', missingFields);
  }

  const clubColumns = [
    'name',
    'category',
    'members',
    'description',
    'color',
    'instagram',
    'telegram',
    'whatsapp',
    'tiktok',
    'youtube',
    'website',
    'creatorId',
    'creatorName',
    'photos',
    'backgroundUrl',
    'backgroundType',
    'clubAvatar'
  ];
  const columnValues = [
    payload.name,
    payload.category,
    1,
    payload.description,
    payload.color,
    payload.instagram,
    payload.telegram,
    payload.whatsapp,
    payload.tiktok,
    payload.youtube,
    payload.website,
    payload.creatorId,
    payload.creatorName,
    payload.photos,
    payload.backgroundUrl,
    payload.backgroundType,
    payload.clubAvatar
  ];
  if (clubColumns.length !== columnValues.length) {
    console.error('Club insert column/value length mismatch', clubColumns.length, columnValues.length);
    return res.status(500).json({ error: 'Неправильное количество полей клуба' });
  }

  db.run(`INSERT INTO clubs (${clubColumns.join(', ')})
          VALUES (${clubColumns.map(() => '?').join(', ')})`,
    columnValues,
    function(err) {
      if (err) {
        console.error('Club creation failed:', { error: err.message, payload });
        return res.status(500).json({ error: err.message || 'Failed to create club' });
      }

      const clubId = this.lastID;
      const joinDate = new Date().toISOString();
      db.run(`INSERT OR IGNORE INTO club_memberships (clubId, userId, joinedAt)
              VALUES (?, ?, ?)`, [clubId, creatorId, joinDate]);

      db.get('SELECT joinedClubs, joinedProjects FROM users WHERE id = ?', [creatorId], (userErr, userRow) => {
        if (!userErr && userRow) {
          let joinedClubs = [];
          try {
            joinedClubs = JSON.parse(userRow.joinedClubs || '[]');
          } catch {
            joinedClubs = [];
          }
          if (!joinedClubs.includes(clubId)) {
            joinedClubs.push(clubId);
            db.run('UPDATE users SET joinedClubs = ? WHERE id = ?', [JSON.stringify(joinedClubs), creatorId]);
          }
        }
        db.get('SELECT * FROM clubs WHERE id = ?', [clubId], (selectErr, club) => {
          if (selectErr) return res.status(500).json({ error: 'Failed to load club' });
          res.json(club);
        });
      });
    });
});

// Join club
app.post('/api/clubs/:id/join', authenticateToken, async (req, res) => {
  try {
    const clubId = parseInt(req.params.id);
    if (!clubId || isNaN(clubId)) {
      return res.status(400).json({ error: 'Invalid club ID' });
    }

    db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, user) => {
      if (err) {
        console.error('DB Error:', err);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!user) {
        return res.status(404).json({ error: 'User not found' });
      }

      try {
        const joinedClubs = JSON.parse(user.joinedClubs || '[]');
        if (joinedClubs.includes(clubId)) {
          return res.status(400).json({ error: 'Already joined' });
        }

        joinedClubs.push(clubId);
        
        db.run('UPDATE users SET joinedClubs = ? WHERE id = ?', [JSON.stringify(joinedClubs), req.user.id], (err) => {
          if (err) {
            console.error('Update error:', err);
            return res.status(500).json({ error: 'Failed to join club' });
          }

          db.run('UPDATE clubs SET members = members + 1 WHERE id = ?', [clubId], (err) => {
            if (err) {
              console.error('Club update error:', err);
              return res.status(500).json({ error: 'Failed to update club' });
            }

            const joinDate = new Date().toISOString();
            db.run(`INSERT OR IGNORE INTO club_memberships (clubId, userId, joinedAt)
                    VALUES (?, ?, ?)`, [clubId, req.user.id, joinDate]);

            res.json({
              id: user.id,
              studentId: user.studentId,
              name: user.name,
              role: user.role,
              avatar: user.avatar,
              isAdmin: user.isAdmin === 1,
              joinedClubs: joinedClubs,
              joinedProjects: JSON.parse(user.joinedProjects || '[]')
            });
          });
        });
      } catch (e) {
        console.error('Parse error:', e);
        return res.status(500).json({ error: 'Error processing request' });
      }
    });
  } catch (error) {
    console.error('Catch error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Leave club
app.delete('/api/clubs/:id/leave', authenticateToken, (req, res) => {
  const clubId = parseInt(req.params.id);
  console.log(`Leave club: clubId=${clubId}, req.params.id=${req.params.id}`);

  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (!user) return res.status(404).json({ error: 'User not found' });

    let joinedClubs = JSON.parse(user.joinedClubs || '[]');
    joinedClubs = joinedClubs.filter(id => id !== clubId);

    db.run('UPDATE users SET joinedClubs = ? WHERE id = ?', [JSON.stringify(joinedClubs), req.user.id], (err) => {
      if (err) return res.status(500).json({ error: 'Failed to leave club' });

      db.run('DELETE FROM club_memberships WHERE clubId = ? AND userId = ?', [clubId, req.user.id]);

      db.run('UPDATE clubs SET members = MAX(0, members - 1) WHERE id = ?', [clubId]);

      res.json({
        id: user.id,
        studentId: user.studentId,
        name: user.name,
        role: user.role,
        avatar: user.avatar,
        isAdmin: user.isAdmin === 1,
        joinedClubs: joinedClubs,
        joinedProjects: JSON.parse(user.joinedProjects || '[]')
      });
    });
  });
});

// Admin: delete club
app.delete('/api/clubs/:id', authenticateToken, requireAdmin, (req, res) => {
  const clubId = parseInt(req.params.id);
  
  db.run('DELETE FROM clubs WHERE id = ?', [clubId], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete club' });
    if (this.changes === 0) return res.status(404).json({ error: 'Club not found' });
    res.json({ success: true });
  });
});

// Get club detail
app.get('/api/clubs/:id', authenticateToken, (req, res) => {
  const clubId = parseInt(req.params.id);
  if (isNaN(clubId)) {
    return res.status(400).json({ error: 'Invalid club ID' });
  }

  db.get('SELECT * FROM clubs WHERE id = ?', [clubId], (err, club) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch club' });
    if (!club) return res.status(404).json({ error: 'Club not found' });

    const photos = (() => {
      try {
        return JSON.parse(club.photos || '[]');
      } catch (parseErr) {
        console.error('Invalid photos JSON for club', clubId, parseErr);
        return [];
      }
    })();

    const buildResponse = (creator) => {
      db.all('SELECT * FROM activities WHERE club = ? ORDER BY createdAt DESC LIMIT 5', [club.name], (activityErr, activityRows) => {
        if (activityErr) {
          return res.status(500).json({ error: 'Failed to fetch activity' });
        }

        res.json({
          ...club,
          photos,
          creator: creator ? { id: creator.id, name: creator.name, username: creator.studentId, avatar: creator.avatar } : null,
          socialLinks: {
            instagram: club.instagram,
            telegram: club.telegram,
            whatsapp: club.whatsapp,
            tiktok: club.tiktok,
            youtube: club.youtube,
            website: club.website
          },
          recentActivity: activityRows || [],
          canManageMembers: club.creatorId === req.user.id
        });
      });
    };

    if (club.creatorId) {
      db.get('SELECT id, name, studentId, avatar FROM users WHERE id = ?', [club.creatorId], (creatorErr, creator) => {
        if (creatorErr) {
          console.error('Failed to fetch creator for club', clubId, creatorErr);
        }
        buildResponse(creator);
      });
    } else {
      buildResponse(null);
    }
  });
});

// Get club members (creator only)
app.get('/api/clubs/:id/members', authenticateToken, (req, res) => {
  const clubId = parseInt(req.params.id);
  if (isNaN(clubId)) {
    return res.status(400).json({ error: 'Invalid club ID' });
  }

  db.get('SELECT creatorId FROM clubs WHERE id = ?', [clubId], (clubErr, club) => {
    if (clubErr) return res.status(500).json({ error: 'Failed to fetch club' });
    if (!club) return res.status(404).json({ error: 'Club not found' });
    if (club.creatorId !== req.user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }

    db.all(
      `SELECT u.id, u.name, u.studentId, u.avatar, cm.joinedAt
       FROM club_memberships cm
       JOIN users u ON cm.userId = u.id
       WHERE cm.clubId = ?
       ORDER BY cm.joinedAt ASC`,
      [clubId],
      (membersErr, rows) => {
        if (membersErr) {
          return res.status(500).json({ error: 'Failed to fetch members' });
        }
        res.json(rows);
      }
    );
  });
});

// Remove club member (creator only)
app.delete('/api/clubs/:clubId/members/:memberId', authenticateToken, (req, res) => {
  const clubId = parseInt(req.params.clubId);
  const memberId = parseInt(req.params.memberId);
  if (isNaN(clubId) || isNaN(memberId)) {
    return res.status(400).json({ error: 'Invalid IDs' });
  }

  db.get('SELECT creatorId FROM clubs WHERE id = ?', [clubId], (clubErr, club) => {
    if (clubErr) return res.status(500).json({ error: 'Failed to fetch club' });
    if (!club) return res.status(404).json({ error: 'Club not found' });
    if (club.creatorId !== req.user.id) {
      return res.status(403).json({ error: 'Only creator can remove members' });
    }
    if (memberId === req.user.id) {
      return res.status(400).json({ error: 'Creator cannot remove themselves' });
    }

    db.run('DELETE FROM club_memberships WHERE clubId = ? AND userId = ?', [clubId, memberId], function(deleteErr) {
      if (deleteErr) return res.status(500).json({ error: 'Failed to remove member' });
      if (this.changes === 0) return res.status(404).json({ error: 'Member not found' });

      db.get('SELECT joinedClubs FROM users WHERE id = ?', [memberId], (userErr, userRow) => {
        if (!userErr && userRow) {
          let joinedClubs = [];
          try {
            joinedClubs = JSON.parse(userRow.joinedClubs || '[]');
          } catch {
            joinedClubs = [];
          }
          const updated = joinedClubs.filter((id) => id !== clubId);
          db.run('UPDATE users SET joinedClubs = ? WHERE id = ?', [JSON.stringify(updated), memberId]);
        }

        db.run('UPDATE clubs SET members = MAX(0, members - 1) WHERE id = ?', [clubId], (clubUpdateErr) => {
          if (clubUpdateErr) {
            console.error('Failed to decrement club members:', clubUpdateErr);
          }
          res.json({ success: true });
        });
      });
    });
  });
});

// ============= SCHEDULE ROUTES =============

// Get schedule
app.get('/api/schedule', authenticateToken, (req, res) => {
  db.all('SELECT * FROM schedule ORDER BY date, time', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch schedule' });
    }
    res.json(rows);
  });
});

// Create schedule item
app.post('/api/schedule', authenticateToken, (req, res) => {
  const { date, time, subject, room, type, color } = req.body;

  db.run(`INSERT INTO schedule (date, time, subject, room, type, color)
          VALUES (?, ?, ?, ?, ?, ?)`,
    [date, time, subject, room, type || 'lecture', color || 'border-blue-500'],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to create schedule item' });

      db.get('SELECT * FROM schedule WHERE id = ?', [this.lastID], (err, item) => {
        res.json(item);
      });
    });
});

// Update schedule item
app.put('/api/schedule/:id', authenticateToken, (req, res) => {
  const { date, time, subject, room, type, color } = req.body;

  db.run(`UPDATE schedule SET date = ?, time = ?, subject = ?, room = ?, type = ?, color = ?
          WHERE id = ?`,
    [date, time, subject, room, type, color, req.params.id],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update schedule item' });

      db.get('SELECT * FROM schedule WHERE id = ?', [req.params.id], (err, item) => {
        res.json(item);
      });
    });
});

// Delete schedule item
app.delete('/api/schedule/:id', authenticateToken, (req, res) => {
  db.run('DELETE FROM schedule WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete schedule item' });
    res.json({ success: true });
  });
});

// ============= PROJECTS ROUTES =============

// Get all projects
app.get('/api/projects', authenticateToken, (req, res) => {
  db.all('SELECT * FROM projects ORDER BY createdAt DESC', (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch projects' });
    }
    
    const projects = rows.map(row => ({
      ...row,
      needed: JSON.parse(row.needed || '[]'),
      neededKeys: JSON.parse(row.neededKeys || '[]')
    }));
    
    res.json(projects);
  });
});

// Create project
app.post('/api/projects', authenticateToken, (req, res) => {
  const { title, status, needed, author, clubId, backgroundUrl, description } = req.body;

  db.run(`INSERT INTO projects (title, status, needed, author, clubId, backgroundUrl, description)
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [title, status, JSON.stringify(needed || []), author, clubId || null, backgroundUrl || '', description || ''],
    function(err) {
      if (err) return res.status(500).json({ error: 'Failed to create project' });

      db.get('SELECT * FROM projects WHERE id = ?', [this.lastID], (err, project) => {
        res.json({
          ...project,
          needed: JSON.parse(project.needed || '[]')
        });
      });
    });
});

// Admin: delete project
app.delete('/api/projects/:id', authenticateToken, requireAdmin, (req, res) => {
  const projectId = parseInt(req.params.id);
  
  db.run('DELETE FROM projects WHERE id = ?', [projectId], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to delete project' });
    if (this.changes === 0) return res.status(404).json({ error: 'Project not found' });
    res.json({ success: true });
  });
});

// ============= PARLIAMENT ROUTES =============

// Helpers for CRUD logic
const fetchAllParliamentMembers = () => new Promise((resolve, reject) => {
  db.all('SELECT * FROM parliament ORDER BY id', (err, rows) => {
    if (err) return reject(err);
    resolve(rows);
  });
});

const createParliamentMember = ({ name, role, position = '', description = '', groupName = '', avatarUrl }) => new Promise((resolve, reject) => {
  const normalize = (value) => (value ? value.trim() : '');
  const cleanedName = normalize(name);
  const cleanedRole = normalize(role);

  if (!cleanedName || !cleanedRole) {
    return reject({ status: 400, message: 'Name and role are required' });
  }

  const [firstName, lastName] = cleanedName.split(/\s+/);
  const fallbackAvatar = buildAvatar(firstName, lastName);

  db.run('INSERT INTO parliament (name, role, position, description, groupName, avatar, avatarUrl) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [cleanedName, cleanedRole, position || '', description || '', groupName || '', fallbackAvatar, avatarUrl || null], function(err) {
      if (err) return reject(err);
      db.get('SELECT * FROM parliament WHERE id = ?', [this.lastID], (selectErr, member) => {
        if (selectErr) return reject(selectErr);
        resolve(member);
      });
    });
});

const updateParliamentMember = (memberId, data) => new Promise((resolve, reject) => {
  const updates = [];
  const params = [];

  const mapField = (field, column) => {
    if (Object.prototype.hasOwnProperty.call(data, field)) {
      updates.push(`${column} = ?`);
      params.push(data[field]);
    }
  };

  mapField('name', 'name');
  mapField('role', 'role');
  mapField('position', 'position');
  mapField('description', 'description');
  mapField('groupName', 'groupName');
  mapField('avatarUrl', 'avatarUrl');

  if (!updates.length) {
    return reject({ status: 400, message: 'No updates provided' });
  }

  params.push(memberId);
  db.run(`UPDATE parliament SET ${updates.join(', ')} WHERE id = ?`, params, function(err) {
    if (err) return reject(err);
    if (this.changes === 0) return reject({ status: 404, message: 'Member not found' });
    db.get('SELECT * FROM parliament WHERE id = ?', [memberId], (err, member) => {
      if (err || !member) return reject({ status: 404, message: 'Member not found' });
      resolve(member);
    });
  });
});

const deleteParliamentMember = (memberId) => new Promise((resolve, reject) => {
  db.run('DELETE FROM parliament WHERE id = ?', [memberId], function(err) {
    if (err) return reject(err);
    if (this.changes === 0) return reject({ status: 404, message: 'Member not found' });
    resolve();
  });
});

// Public endpoints
app.get('/api/parliament', authenticateToken, async (_req, res) => {
  try {
    const rows = await fetchAllParliamentMembers();
    res.json(rows);
  } catch (err) {
    console.error('Failed to fetch parliament:', err);
    res.status(500).json({ error: 'Failed to fetch parliament' });
  }
});

app.get('/api/parliament/getAll', authenticateToken, async (_req, res) => {
  try {
    const rows = await fetchAllParliamentMembers();
    res.json(rows);
  } catch (err) {
    console.error('GetAll failed:', err);
    res.status(500).json({ error: 'Failed to fetch parliament members' });
  }
});

// Admin endpoints
app.post('/api/parliament', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const member = await createParliamentMember(req.body);
    res.json(member);
  } catch (err) {
    console.error('Failed to add member:', err);
    const status = err?.status || 500;
    res.status(status).json({ error: err?.message || 'Failed to add member' });
  }
});

app.post('/api/parliament/add', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const member = await createParliamentMember(req.body);
    res.json(member);
  } catch (err) {
    console.error('Add failed:', err);
    const status = err?.status || 500;
    res.status(status).json({ error: err?.message || 'Failed to add member' });
  }
});

app.put('/api/parliament/:id', authenticateToken, requireAdmin, async (req, res) => {
  const memberId = parseInt(req.params.id, 10);
  try {
    const updated = await updateParliamentMember(memberId, req.body);
    res.json(updated);
  } catch (err) {
    console.error('Failed to update member:', err);
    const status = err?.status || 500;
    res.status(status).json({ error: err?.message || 'Failed to update member' });
  }
});

app.put('/api/parliament/update/:id', authenticateToken, requireAdmin, async (req, res) => {
  const memberId = parseInt(req.params.id, 10);
  try {
    const updated = await updateParliamentMember(memberId, req.body);
    res.json(updated);
  } catch (err) {
    console.error('Update failed:', err);
    const status = err?.status || 500;
    res.status(status).json({ error: err?.message || 'Failed to update member' });
  }
});

app.put('/api/parliament/:id/avatar', authenticateToken, requireAdmin, (req, res) => {
  const { avatarUrl } = req.body;

  db.run('UPDATE parliament SET avatarUrl = ? WHERE id = ?', [avatarUrl, req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Failed to update avatar' });

    db.get('SELECT * FROM parliament WHERE id = ?', [req.params.id], (err, member) => {
      res.json(member);
    });
  });
});

app.delete('/api/parliament/:id', authenticateToken, requireAdmin, async (req, res) => {
  const memberId = parseInt(req.params.id, 10);
  try {
    await deleteParliamentMember(memberId);
    res.json({ success: true });
  } catch (err) {
    console.error('Failed to delete member:', err);
    const status = err?.status || 500;
    res.status(status).json({ error: err?.message || 'Failed to delete member' });
  }
});

app.delete('/api/parliament/remove/:id', authenticateToken, requireAdmin, async (req, res) => {
  const memberId = parseInt(req.params.id, 10);
  try {
    await deleteParliamentMember(memberId);
    res.json({ success: true });
  } catch (err) {
    console.error('Remove failed:', err);
    const status = err?.status || 500;
    res.status(status).json({ error: err?.message || 'Failed to remove member' });
  }
});

// ============= ACTIVITIES ROUTES =============

// Get user activities
app.get('/api/activities', authenticateToken, (req, res) => {
  db.all('SELECT * FROM activities WHERE userId = ? ORDER BY createdAt DESC LIMIT 20', 
    [req.user.id], 
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to fetch activities' });
      }
      res.json(rows);
    });
});

// Feedback accept endpoint - sends email to user
app.post('/api/feedback/accept', authenticateToken, requireAdmin, async (req, res) => {
  const { email, name, subject } = req.body;

  try {
    // Email content
    const emailContent = {
      from: '"College Hub Support" <noreply@collegehub.com>',
      to: email,
      subject: `✓ Ваше обращение принято - ${subject}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
          <div style="background: linear-gradient(135deg, #0284c7 0%, #0ea5e9 100%); color: white; padding: 20px; border-radius: 10px; text-align: center; margin-bottom: 20px;">
            <h2 style="margin: 0; font-size: 24px;">✓ Спасибо!</h2>
          </div>
          
          <p>Здравствуйте, <strong>${name}</strong>!</p>
          
          <p>Ваше обращение с темой <strong>"${subject}"</strong> успешно принято нашей командой.</p>
          
          <div style="background: #f0f9ff; border-left: 4px solid #0284c7; padding: 15px; margin: 20px 0; border-radius: 5px;">
            <p style="margin: 0; color: #0284c7;">
              <strong>Статус:</strong> В обработке
            </p>
            <p style="margin: 5px 0 0 0; color: #666; font-size: 14px;">
              Мы проанализируем ваше сообщение и свяжемся с вами в ближайшее время.
            </p>
          </div>
          
          <p style="color: #666; font-size: 14px; margin-top: 20px;">
            Если вы хотите добавить информацию к вашему обращению, просто ответьте на это письмо.
          </p>
          
          <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 20px 0;">
          
          <p style="color: #999; font-size: 12px; text-align: center;">
            College Hub Support Team<br>
            © 2025 College Hub. Все права защищены.
          </p>
        </div>
      `
    };

    // Send email if transporter is available
    if (emailTransporter) {
      const info = await emailTransporter.sendMail(emailContent);
      console.log('✅ Email sent successfully!');
      console.log('   To:', email);
      console.log('   Subject:', emailContent.subject);
      
      // If using Ethereal test account, show the preview URL
      if (process.env.NODE_ENV !== 'production' && !hasGmailConfig) {
        const testUrl = nodemailer.getTestMessageUrl(info);
        if (testUrl) {
          console.log('   📧 Preview URL:', testUrl);
          res.json({ 
            success: true, 
            message: 'Email sent successfully',
            previewUrl: testUrl 
          });
          return;
        }
      }
      
      res.json({ success: true, message: 'Email sent successfully' });
    } else {
      // Fallback if transporter not ready yet
      console.log('📧 [DEV MODE] Email would be sent to:', email);
      console.log('   Subject:', emailContent.subject);
      console.log('   To:', name);
      res.json({ success: true, message: 'Feedback received (email not sent - transporter not ready)' });
    }
  } catch (err) {
    console.error('Failed to process feedback:', err);
    res.status(500).json({ error: 'Failed to process feedback: ' + err.message });
  }
});

// Global error handler
app.use((err, req, res, _next) => {
  void _next;
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
    console.error('Verify that nothing else is using the port and try again.');
    process.exit(1);
  });

  // Graceful shutdown
  process.on('SIGINT', () => {
    db.close((err) => {
      if (err) {
        console.error('Error closing database:', err.message);
      }
      console.log('Database connection closed');
      process.exit(0);
    });
  });
}

// Export for Vercel
module.exports = app;
