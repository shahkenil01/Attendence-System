// database.js
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');

async function setup() {
  // open the database file
  const db = await open({
    filename: './attendance.db', // This file will be created
    driver: sqlite3.Database
  });

  // Create the 'users' table if it doesn't exist
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      enrollment TEXT UNIQUE, -- Enrollment must be unique for students
      email TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('student', 'teacher'))
    );
  `);

  console.log('Database setup complete.');
  return db;
}

// Export the setup function so we can use it in our server
module.exports = setup;