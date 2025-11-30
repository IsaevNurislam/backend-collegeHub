const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const dbPath = path.join(__dirname, '..', 'database.sqlite');

if (!fs.existsSync(dbPath)) {
  console.error('SQLite database file missing at', dbPath);
  process.exit(1);
}

const db = new sqlite3.Database(dbPath, sqlite3.OPEN_READWRITE, (err) => {
  if (err) {
    console.error('Unable to open database:', err.message);
    process.exit(1);
  }

  db.get('SELECT 1 as ok', (queryErr) => {
    if (queryErr) {
      console.error('Database response invalid:', queryErr.message);
      process.exit(1);
    }

    console.log('SQLite health check passed');
    db.close(() => process.exit(0));
  });
});