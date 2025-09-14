require('dotenv').config({ quiet: true });
const express = require('express');
const jwt = require('jsonwebtoken');
const http = require('http');
const { Server } = require('socket.io');
const path = require('path');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const connectDB = require('./database');
const User = require('./models/User');

connectDB();

const app = express();
app.set('trust proxy', true);
const server = http.createServer(app);
const io = new Server(server);

// --- MIDDLEWARE SETUP ---
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'your-default-secret-key';

// **FIXED: Socket.IO Authentication Middleware**
// Is section ko update kiya gaya hai
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error('Authentication error: No token provided.'));
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const dbUser = await User.findById(decoded.id);

    if (!dbUser || dbUser.currentDevice !== decoded.deviceId) {
      return next(
        new Error(
          'Authentication error: Session expired or logged in elsewhere.',
        ),
      );
    }

    socket.user = decoded;
    next();
  } catch (err) {
    return next(new Error('Authentication error: Invalid token.'));
  }
});

// --- GLOBAL VARIABLES & CONFIG ---
let waitingRoom = [];
let currentSession = { code: null, subject: 'No Subject' };
let finalAttendanceList = [];
let blockedList = [];
let isSessionLocked = false;
const activeUsers = new Map();

const CAMPUS_LOCATION = {
  latitude: 23.0830809,
  longitude: 72.5341933,
  radius: 60,
};

function getDistance(lat1, lon1, lat2, lon2) {
  const R = 6371e3;
  const φ1 = (lat1 * Math.PI) / 180;
  const φ2 = (lat2 * Math.PI) / 180;
  const Δφ = ((lat2 - lat1) * Math.PI) / 180;
  const Δλ = ((lon2 - lon1) * Math.PI) / 180;
  const a =
    Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
    Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

// --- SERVER LOGIC ---

const protectRoute = async (req, res, next) => {
  const token = req.cookies.authToken;
  if (!token) {
    return res.redirect('/login');
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const dbUser = await User.findById(decoded.id);

    if (!dbUser || dbUser.currentDevice !== decoded.deviceId) {
      res.clearCookie('authToken');
      return res.redirect('/login');
    }

    req.user = decoded;
    next();
  } catch (error) {
    res.clearCookie('authToken');
    return res.redirect('/login');
  }
};

// --- PUBLIC ROUTES ---
app.get('/', (req, res) => res.redirect('/login'));
app.get('/login', (req, res) =>
  res.sendFile(path.join(__dirname, 'views', 'login.html')),
);
app.get('/signup', (req, res) =>
  res.sendFile(path.join(__dirname, 'views', 'signup.html')),
);

app.post('/signup', async (req, res) => {
  try {
    const { name, email, password, role, enrollment, subjects } = req.body;
    if (!name || !email || !password || !role) {
      return res
        .status(400)
        .json({ success: false, message: 'Please fill all required fields.' });
    }
    if (role === 'student' && !enrollment) {
      return res.status(400).json({
        success: false,
        message: 'Enrollment number is required for students.',
      });
    }

    let user = await User.findOne({ email });
    if (user) {
      return res
        .status(400)
        .json({ success: false, message: 'Email already exists.' });
    }
    if (role === 'student' && enrollment) {
      user = await User.findOne({ enrollment });
      if (user) {
        return res.status(400).json({
          success: false,
          message: 'Enrollment number already exists.',
        });
      }
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({
      name,
      email,
      password: hashedPassword,
      role,
      enrollment,
      subjects,
    });
    await user.save();

    res
      .status(201)
      .json({ success: true, message: 'Signup successful! Please login.' });
  } catch (error) {
    console.error('Signup error:', error);
    res
      .status(500)
      .json({ success: false, message: 'Server error during signup.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body; // Ab client se koi ID nahi aa rahi

    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res
        .status(401)
        .json({ success: false, message: 'Invalid credentials.' });
    }

    // **Asli Device ID ab sirf user ka IP Address hai**
    const deviceId = req.ip;

    const alreadyLogged = await User.findOne({
      currentDevice: deviceId, // Check karo ki is IP se koi aur to logged in nahi hai
      _id: { $ne: user._id },
    });

    if (alreadyLogged) {
      return res.status(403).json({
        success: false,
        message: `This IP Address is already in use by another account (${alreadyLogged.email}). Logout first.`,
      });
    }

    // User ke record mein IP address ko save karo
    user.currentDevice = deviceId;
    await user.save();

    const payload = {
      id: user.id,
      name: user.name,
      role: user.role,
      enrollment: user.enrollment,
      deviceId: deviceId, // Token mein bhi IP address hi jayega
    };

    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '3h' });

    res.cookie('authToken', token, { httpOnly: true, sameSite: 'strict' });
    res.json({
      success: true,
      message: 'Login Successful! Redirecting...',
      token: token,
      user: { role: user.role },
    });
  } catch (error) {
    console.error('Login error:', error);
    res
      .status(500)
      .json({ success: false, message: 'Server error during login.' });
  }
});

// --- GATEKEEPER ---
app.use(protectRoute);

// --- PROTECTED ROUTES ---
app.get('/student', (req, res) => {
  if (req.user.role !== 'student') return res.redirect('/teacher');
  res.sendFile(path.join(__dirname, 'views', 'student.html'));
});
app.get('/teacher', (req, res) => {
  if (req.user.role !== 'teacher') return res.redirect('/student');
  res.sendFile(path.join(__dirname, 'views', 'teacher.html'));
});
app.get('/form', (req, res) => {
  if (req.user.role !== 'student') return res.redirect('/teacher');
  res.sendFile(path.join(__dirname, 'views', 'form.html'));
});
app.get('/logout', async (req, res) => {
  try {
    if (req.user && req.user.id) {
      await User.findByIdAndUpdate(req.user.id, {
        $set: { currentDevice: null },
      });
    }
  } catch (error) {
    console.error('Error clearing device on logout:', error);
  }
  res.clearCookie('authToken');
  res.redirect('/login');
});
app.get('/api/user/me', (req, res) => {
  if (!req.user) {
    return res
      .status(401)
      .json({ success: false, message: 'Not authenticated' });
  }
  res.json({
    success: true,
    user: {
      name: req.user.name,
      enrollment: req.user.enrollment,
      role: req.user.role,
      subjects: req.user.subjects,
    },
  });
});

// --- SOCKET.IO LOGIC ---
io.on('connection', (socket) => {
  console.log('socket connected', socket.id, 'as', socket.user.name);

  const existingSocketId = activeUsers.get(socket.user.id);
  if (existingSocketId && existingSocketId !== socket.id) {
    io.to(existingSocketId).emit('forceDisconnect');
  }

  activeUsers.set(socket.user.id, socket.id);

  socket.on('verifyLocation', (coords) => {
    if (socket.user.role !== 'student' || !coords) return;
    const distance = getDistance(
      CAMPUS_LOCATION.latitude,
      CAMPUS_LOCATION.longitude,
      coords.latitude,
      coords.longitude,
    );
    if (distance <= CAMPUS_LOCATION.radius) {
      socket.emit('locationVerified');
    } else {
      socket.emit(
        'locationInvalid',
        `You are ~${Math.round(distance)} meters away. You must be within ${
          CAMPUS_LOCATION.radius
        } meters of the campus.`,
      );
    }
  });

  socket.on('startSession', (data) => {
    if (socket.user.role !== 'teacher' || !data || !data.subject) return;
    currentSession.code = Math.floor(100000000 + Math.random() * 900000000);
    currentSession.subject = data.subject;
    currentSession.location = data.location;
    waitingRoom = [];
    finalAttendanceList = [];
    blockedList = [];
    isSessionLocked = false;
    io.emit('sessionCode', currentSession.code);
    io.emit('attendanceUpdate', finalAttendanceList);
    console.log(
      `New session for "${currentSession.subject}" started with code ${currentSession.code}`,
    );
  });

  socket.on('joinWaiting', (data) => {
    if (isSessionLocked) {
      return socket.emit(
        'errorMsg',
        'This session has been locked by the teacher.',
      );
    }
    if (
      socket.user.role !== 'student' ||
      !data ||
      data.code != currentSession.code
    ) {
      return socket.emit('errorMsg', 'Invalid session code');
    }
    if (blockedList.includes(socket.user.enrollment)) {
      return socket.emit(
        'errorMsg',
        'You have been removed and cannot rejoin.',
      );
    }
    const studentExists = waitingRoom.find(
      (s) => s.enrollment === socket.user.enrollment,
    );
    if (!studentExists) {
      waitingRoom.push({
        id: socket.id,
        name: socket.user.name,
        enrollment: socket.user.enrollment,
      });
    }
    socket.emit('joinSuccess', { subject: currentSession.subject });
    io.emit('waitingList', waitingRoom);
  });

  socket.on('removeStudent', (enrollment) => {
    if (socket.user.role !== 'teacher') return;
    const studentToRemove = waitingRoom.find(
      (s) => s.enrollment === enrollment,
    );
    waitingRoom = waitingRoom.filter((s) => s.enrollment !== enrollment);
    blockedList.push(enrollment);
    io.emit('waitingList', waitingRoom);
    if (studentToRemove) {
      io.to(studentToRemove.id).emit('youAreRemoved');
    }
    console.log(`Teacher ${socket.user.name} removed student ${enrollment}`);
  });

  socket.on('verifyFinalLocation', (studentCoords) => {
    if (
      socket.user.role !== 'student' ||
      !studentCoords ||
      !currentSession.location
    ) {
      return;
    }

    const CLASSROOM_RADIUS = 20;

    const distance = getDistance(
      currentSession.location.lat,
      currentSession.location.lon,
      studentCoords.latitude,
      studentCoords.longitude,
    );

    if (distance <= CLASSROOM_RADIUS) {
      socket.emit('finalLocationVerified');
    } else {
      socket.emit(
        'finalLocationInvalid',
        `You must be in the classroom (~${Math.round(distance)}m away).`,
      );
    }
  });

  socket.on('lockSession', () => {
    if (socket.user.role !== 'teacher') return;
    isSessionLocked = true;
    io.emit('goToForm');
    console.log('Teacher locked session. No new students can join.');
  });

  socket.on('submitAttendance', () => {
    if (socket.user.role !== 'student') return;
    const studentExists = finalAttendanceList.find(
      (s) => s.enrollment === socket.user.enrollment,
    );
    if (!studentExists) {
      const submission = {
        name: socket.user.name,
        enrollment: socket.user.enrollment,
        timestamp: new Date().toLocaleTimeString('en-IN', {
          timeZone: 'Asia/Kolkata',
        }),
      };
      finalAttendanceList.push(submission);
      io.emit('attendanceUpdate', finalAttendanceList);
    }
  });

  socket.on('getReport', () => {
    if (socket.user.role !== 'teacher' || finalAttendanceList.length === 0)
      return;
    const headers = ['Enrollment No', 'Name', 'Timestamp'];
    const dataRows = finalAttendanceList.map((s) => [
      s.enrollment,
      s.name,
      s.timestamp,
    ]);
    const csvContent = [headers, ...dataRows]
      .map((row) => row.join(','))
      .join('\n');
    socket.emit('reportData', csvContent);
  });

  socket.on('disconnect', () => {
    if (activeUsers.get(socket.user.id) === socket.id) {
      activeUsers.delete(socket.user.id);
    }
    waitingRoom = waitingRoom.filter((s) => s.id !== socket.id);
    io.emit('waitingList', waitingRoom);
    console.log('socket disconnected', socket.id);
  });
});

// --- START SERVER ---
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
