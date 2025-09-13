// models/User.js
const mongoose = require('mongoose');

const UserSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, required: true, enum: ['student', 'teacher'] },
    enrollment: { type: String, unique: true, sparse: true }, // sparse: true allows multiple nulls
    subjects: { type: String }
});

module.exports = mongoose.model('User', UserSchema);