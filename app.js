const express = require('express');
const session = require('express-session');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// CSP header middleware
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'none'; " +
    "script-src 'self' https://cdn.jsdelivr.net; " +
    "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self';"
  );
  next();
});

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(session({
  secret: 'ctf-lab-secret',
  resave: false,
  saveUninitialized: true,
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// User DB (in-memory for demo)
const USERS = {
  'admin': { password: 'admin', id: '1243315' },
  'bob': { password: 'hunter2', id: '2222222' }
};

// Multer setup for file uploads
const uploadDir = path.join(__dirname, 'user');
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const userDir = path.join(uploadDir, req.session.userid || 'guest');
    if (!fs.existsSync(userDir)) fs.mkdirSync(userDir);
    cb(null, userDir);
  },
  filename: function (req, file, cb) {
    cb(null, file.originalname);
  }
});
const upload = multer({ storage });

// Auth middleware
function requireLogin(req, res, next) {
  if (!req.session.userid) return res.redirect('/login');
  next();
}

// Login routes
app.get('/login', (req, res) => {
  res.render('login', { error: null });
});
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (USERS[username] && USERS[username].password === password) {
    req.session.userid = USERS[username].id;
    // Set flag cookie for CTF
    if (!req.cookies.flag) {
      res.cookie('flag', 'CTF{C5P_15_BR34K4BL3_W1TH_UPL04D}', { httpOnly: false });
    }
    return res.redirect('/');
  }
  res.render('login', { error: 'Invalid credentials' });
});
app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

// Home page
app.get('/', requireLogin, (req, res) => {
  res.render('index', { userid: req.session.userid });
});

// File upload
app.get('/upload', requireLogin, (req, res) => {
  res.render('upload', { userid: req.session.userid, uploaded: null });
});
app.post('/upload', requireLogin, upload.single('file'), (req, res) => {
  if (!req.file) return res.render('upload', { userid: req.session.userid, uploaded: 'No file uploaded.' });
  if (!req.file.originalname.endsWith('.js')) {
    fs.unlinkSync(req.file.path);
    return res.render('upload', { userid: req.session.userid, uploaded: 'Not the secret file' });
  }
  const fileUrl = `/user/${req.session.userid}/${req.file.originalname}`;
  res.render('upload', { userid: req.session.userid, uploaded: fileUrl });
});

// Serve uploaded JS files with correct Content-Type
app.get('/user/:userid/:filename', (req, res) => {
  const { userid, filename } = req.params;
  const filePath = path.join(uploadDir, userid, filename);
  if (fs.existsSync(filePath)) {
    res.type('application/javascript');
    return res.sendFile(filePath);
  }
  res.status(404).send('File not found');
});

// XSS-vulnerable page
app.get('/profile', requireLogin, (req, res) => {
  // Reflects the 'bio' query param unsanitized
  const bio = req.query.bio || '';
  res.render('profile', { userid: req.session.userid, bio });
});

// Flag reveal endpoint (for demo/testing)
app.get('/flag', requireLogin, (req, res) => {
  if (req.cookies.flag) {
    res.send(`Your flag: ${req.cookies.flag}`);
  } else {
    res.send('No flag for you!');
  }
});

app.listen(PORT, () => {
  console.log(`Upload The Policy running at http://localhost:${PORT}`);
}); 