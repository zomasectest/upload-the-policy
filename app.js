const express = require('express');
const session = require('express-session');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3000;

// Vulnerable XSS filter function - FOR EDUCATIONAL PURPOSES ONLY
function vulnerableXSSFilter(input) {
  if (!input) return input;
  
  // Flawed filter that only removes simple tags with a-z, A-Z characters
  // This creates multiple bypass opportunities:
  
  // 1. Only removes tags with alphabetic characters
  // 2. Case sensitive in some places
  // 3. Doesn't handle nested tags properly
  // 4. Doesn't filter attributes
  // 5. Doesn't handle encoded characters
  
  let filtered = input;
  
  // Remove simple tags like <script>, <img>, <a>, etc.
  // But this regex is flawed and can be bypassed
  filtered = filtered.replace(/<([a-zA-Z]+)[^>]*>/gi, '');
  filtered = filtered.replace(/<\/([a-zA-Z]+)>/gi, '');
  
  return filtered;
}

// More sophisticated but still vulnerable filter
function advancedVulnerableFilter(input) {
  if (!input) return input;
  
  let filtered = input;
  
  // Remove obvious XSS patterns but with flaws
  const dangerousPatterns = [
    /<script/gi,
    /<\/script>/gi,
    /javascript:/gi,
    /on\w+\s*=/gi,  // onclick, onload, etc.
  ];
  
  dangerousPatterns.forEach(pattern => {
    filtered = filtered.replace(pattern, '');
  });
  
  // Flawed tag removal - only removes complete tags
  filtered = filtered.replace(/<([a-zA-Z]+)(\s+[^>]*)?>/gi, '');
  filtered = filtered.replace(/<\/([a-zA-Z]+)>/gi, '');
  
  return filtered;
}

// CSP header middleware with intentional weaknesses
app.use((req, res, next) => {
  const nonce = Buffer.from(require('crypto').randomBytes(16)).toString('base64');
  res.locals.nonce = nonce;
  
  // Intentionally weak CSP for the lab
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
      res.cookie('flag', 'CTF{XSS_F1LT3R_BYPA55_M45T3R}', { httpOnly: false });
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

// XSS-vulnerable page with flawed filtering
app.get('/profile', requireLogin, (req, res) => {
  const bio = req.query.bio || '';
  
  // Apply vulnerable filter
  const filteredBio = vulnerableXSSFilter(bio);
  
  res.render('profile', { 
    userid: req.session.userid, 
    bio: filteredBio,
    originalBio: bio // Show original for debugging
  });
});

// Advanced XSS challenge with stronger but still vulnerable filter
app.get('/advanced-profile', requireLogin, (req, res) => {
  const bio = req.query.bio || '';
  
  // Apply more sophisticated but still vulnerable filter
  const filteredBio = advancedVulnerableFilter(bio);
  
  res.render('advanced-profile', { 
    userid: req.session.userid, 
    bio: filteredBio,
    originalBio: bio
  });
});

// XSS testing endpoint - shows what the filter does
app.get('/test-filter', requireLogin, (req, res) => {
  const input = req.query.input || '';
  const basic = vulnerableXSSFilter(input);
  const advanced = advancedVulnerableFilter(input);
  
  res.json({
    original: input,
    basicFilter: basic,
    advancedFilter: advanced
  });
});

// Flag reveal endpoint
app.get('/flag', requireLogin, (req, res) => {
  if (req.cookies.flag) {
    res.send(`Your flag: ${req.cookies.flag}`);
  } else {
    res.send('No flag for you!');
  }
});

// XSS challenge hints endpoint
app.get('/hints', requireLogin, (req, res) => {
  const hints = [
    "The filter only removes tags with alphabetic characters (a-z, A-Z)",
    "What about numbers or special characters in tag names?",
    "Nested tags might not be handled properly",
    "Try malformed HTML structures",
    "Event handlers might slip through",
    "Consider HTML entities and encoding",
    "The advanced filter is more restrictive but still has flaws"
  ];
  
  res.render('hints', { hints, userid: req.session.userid });
});

app.listen(PORT, () => {
  console.log(`XSS Filter Bypass Lab running at http://localhost:${PORT}`);
  console.log(`\nCHALLENGE OBJECTIVES:`);
  console.log(`1. Bypass the basic XSS filter on /profile`);
  console.log(`2. Bypass the advanced filter on /advanced-profile`);
  console.log(`3. Execute JavaScript to steal the flag cookie`);
  console.log(`4. Use /test-filter to test your payloads`);
  console.log(`5. Visit /hints for guidance`);
  console.log(`\nExample vulnerable payloads to try:`);
  console.log(`- <img src=x onerror=alert(1)>`);
  console.log(`- <svg onload=alert(1)>`);
  console.log(`- <1 onmouseover=alert(1)>hover</1>`);
  console.log(`- <script>alert(1)</script>`);
});




// const express = require('express');
// const session = require('express-session');
// const multer = require('multer');
// const cookieParser = require('cookie-parser');
// const path = require('path');
// const fs = require('fs');

// const app = express();
// const PORT = 3000;

// // CSP header middleware
// app.use((req, res, next) => {
//   // res.setHeader(
//   //   'Content-Security-Policy',
//   //   "default-src 'none'; " +
//   //   "script-src 'self' https://cdn.jsdelivr.net; " +
//   //   "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; " +
//   //   "font-src 'self' https://fonts.gstatic.com; " +
//   //   "img-src 'self';"
//   // );
//     // Generate a random nonce for each request
//     const nonce = Buffer.from(require('crypto').randomBytes(16)).toString('base64');
//     res.locals.nonce = nonce;
  
//     res.setHeader(
//     'Content-Security-Policy',
//     "default-src 'none'; " +
//     `script-src 'self' https://cdn.jsdelivr.net 'nonce-${nonce}'; ` +
//     "style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com 'unsafe-inline'; " +
//     "font-src 'self' https://fonts.gstatic.com; " +
//     "img-src 'self';"
//   );
//   next();
// });

// app.use(express.urlencoded({ extended: true }));
// app.use(cookieParser());
// app.use(session({
//   secret: 'ctf-lab-secret',
//   resave: false,
//   saveUninitialized: true,
// }));

// app.set('view engine', 'ejs');
// app.set('views', path.join(__dirname, 'views'));

// // User DB (in-memory for demo)
// const USERS = {
//   'admin': { password: 'admin', id: '1243315' },
//   'bob': { password: 'hunter2', id: '2222222' }
// };

// // Multer setup for file uploads
// const uploadDir = path.join(__dirname, 'user');
// if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);
// const storage = multer.diskStorage({
//   destination: function (req, file, cb) {
//     const userDir = path.join(uploadDir, req.session.userid || 'guest');
//     if (!fs.existsSync(userDir)) fs.mkdirSync(userDir);
//     cb(null, userDir);
//   },
//   filename: function (req, file, cb) {
//     cb(null, file.originalname);
//   }
// });
// const upload = multer({ storage });

// // Auth middleware
// function requireLogin(req, res, next) {
//   if (!req.session.userid) return res.redirect('/login');
//   next();
// }

// // Login routes
// app.get('/login', (req, res) => {
//   res.render('login', { error: null });
// });
// app.post('/login', (req, res) => {
//   const { username, password } = req.body;
//   if (USERS[username] && USERS[username].password === password) {
//     req.session.userid = USERS[username].id;
//     // Set flag cookie for CTF
//     if (!req.cookies.flag) {
//       res.cookie('flag', 'CTF{C5P_15_BR34K4BL3_W1TH_UPL04D}', { httpOnly: false });
//     }
//     return res.redirect('/');
//   }
//   res.render('login', { error: 'Invalid credentials' });
// });
// app.get('/logout', (req, res) => {
//   req.session.destroy(() => res.redirect('/login'));
// });

// // Home page
// app.get('/', requireLogin, (req, res) => {
//   res.render('index', { userid: req.session.userid });
// });

// // File upload
// app.get('/upload', requireLogin, (req, res) => {
//   res.render('upload', { userid: req.session.userid, uploaded: null });
// });
// app.post('/upload', requireLogin, upload.single('file'), (req, res) => {
//   if (!req.file) return res.render('upload', { userid: req.session.userid, uploaded: 'No file uploaded.' });
//   if (!req.file.originalname.endsWith('.js')) {
//     fs.unlinkSync(req.file.path);
//     return res.render('upload', { userid: req.session.userid, uploaded: 'Not the secret file' });
//   }
//   const fileUrl = `/user/${req.session.userid}/${req.file.originalname}`;
//   res.render('upload', { userid: req.session.userid, uploaded: fileUrl });
// });

// // Serve uploaded JS files with correct Content-Type
// app.get('/user/:userid/:filename', (req, res) => {
//   const { userid, filename } = req.params;
//   const filePath = path.join(uploadDir, userid, filename);
//   if (fs.existsSync(filePath)) {
//     res.type('application/javascript');
//     return res.sendFile(filePath);
//   }
//   res.status(404).send('File not found');
// });

// // XSS-vulnerable page
// app.get('/profile', requireLogin, (req, res) => {
//   // Reflects the 'bio' query param unsanitized
//   const bio = req.query.bio || '';
//   res.render('profile', { userid: req.session.userid, bio });
// });

// // Flag reveal endpoint (for demo/testing)
// app.get('/flag', requireLogin, (req, res) => {
//   if (req.cookies.flag) {
//     res.send(`Your flag: ${req.cookies.flag}`);
//   } else {
//     res.send('No flag for you!');
//   }
// });

// app.listen(PORT, () => {
//   console.log(`Upload The Policy running at http://localhost:${PORT}`);
// }); 