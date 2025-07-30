const express = require('express');
const session = require('express-session');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

function vulnerableXSSFilter(input) {
  if (!input) return input;

  
  let filtered = input;
  

  filtered = filtered.replace(/<([a-zA-Z]+)[^>]*>/gi, '');
  filtered = filtered.replace(/<\/([a-zA-Z]+)>/gi, '');
  
  return filtered;
}

function inputFilter(input) {
  if (!input) return input;
  
  let filtered = input;
  
  const dangerousPatterns = [
    /<script/gi,
    /<\/script>/gi,
    /javascript:/gi,
  ];
  dangerousPatterns.forEach(pattern => {
    filtered = filtered.replace(pattern, '');
  });

  filtered = filtered.replace(/<([a-zA-Z]+)(\s+[^>]*)?>/gi, '');
  filtered = filtered.replace(/<\/([a-zA-Z]+)>/gi, '');
  
  return filtered;
}

function scriptTagFilter(input) {
  if (!input) return input;

  return input
    // Remove any tag that *starts* with <scrip or <script (even broken or obfuscated)
    .replace(/<\s*s\s*c\s*r\s*i\s*p[^>]*>?/gim, '')
    // Remove any closing </script> tags (even broken or obfuscated)
    .replace(/<\s*\/\s*s\s*c\s*r\s*i\s*p\s*t\s*>/gim, '')
    // Remove inline event handlers like onerror=, onclick=, etc.
    .replace(/\s+on\w+\s*=\s*(['"]).*?\1/gi, '')
    // Remove src attribute that points to remote js
    .replace(/\s+src\s*=\s*(['"])?[^'">]+\1?/gi, '');
}


app.use((req, res, next) => {
  const nonce = Buffer.from(require('crypto').randomBytes(16)).toString('base64');
  res.locals.nonce = nonce;
  

  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
    `script-src 'self' https://cdn.jsdelivr.net 'nonce-${nonce}' 'unsafe-inline'; ` +
    "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; " +
    "font-src 'self' https://fonts.gstatic.com; " +
    "img-src 'self' data:; " +
    "object-src 'none';"
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

const USERS = {
  'admin': { password: 'admin', id: '1243315' },
};

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


function requireLogin(req, res, next) {
  if (!req.session.userid) return res.redirect('/login');
  next();
}


app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (USERS[username] && USERS[username].password === password) {
    req.session.userid = USERS[username].id;
   
    if (!req.cookies.flag) {
      res.cookie('flag', 'CTF{XSS_F1LT3R_BYPA55_M45T3R}', { httpOnly: false });
    }
    return res.redirect('/');
  }
  res.render('login', { error: 'Invalid credentials' });
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});


app.get('/', requireLogin, (req, res) => {
  res.render('index', { userid: req.session.userid });
});

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


app.get('/user/:userid/:filename', (req, res) => {
  const { userid, filename } = req.params;
  const filePath = path.join(uploadDir, userid, filename);
  if (fs.existsSync(filePath)) {
    res.type('application/javascript');
    return res.sendFile(filePath);
  }
  res.status(404).send('File not found');
});


app.get('/profile', requireLogin, (req, res) => {
  const bio = req.query.bio || '';

  // Check for <script> tag or "script" keyword (case-insensitive)
  const scriptRegex = /<\s*script\b|script\b/i;
  if (scriptRegex.test(bio)) {
    return res.status(403).send('Forbidden: script tag or keyword detected');
  }

  const filteredBio = inputFilter(bio);
  const scriptFiltered = scriptTagFilter(filteredBio)
  
  res.render('profile', { 
    userid: req.session.userid, 
    bio: scriptFiltered,
    originalBio: bio 
  });
});


// XSS challenge hints endpoint
app.get('/hints', requireLogin, (req, res) => {
  const hints = [
    "1: If your life's line is hard try a new line",
    "2: They say identities can be stolen, but what if you could replace one?",
    "3: When you can’t call help from outside, try hiring someone inside and teach him the name they trust.",
  ];
  
  res.json({ hints });
});

app.get('/leaderboard', requireLogin, (req, res) => {
  // Placeholder leaderboard data
  const leaderboard = [
    { username: 'MushroomWasp', rank: 1 },
    { username: 'caesareg', rank: 2 },
    { username: 'Al_Muthanna_0x8', rank: 3 },
    { username: 'Loay Ahmed', rank: 4 },
  ];
  res.render('leaderboard', { leaderboard, userid: req.session.userid });
});

app.listen(PORT, () => {
  console.log(`Upload The Policy Lab running at http://localhost:${PORT}`);
  
});


