const express  = require('express');
const fs        = require('fs');
const path      = require('path');
const crypto    = require('crypto');
const bcrypt    = require('bcryptjs');
const session   = require('express-session');

const app       = express();
const PORT      = process.env.PORT || 3002;
const VIEWS     = path.join(__dirname, 'views');
const TASKS_FILE  = path.join(__dirname, 'tasks.json');
const USERS_FILE  = path.join(__dirname, 'users.json');
const SECRET_FILE = path.join(__dirname, '.session-secret');

// ── Session secret (generated once, persisted across restarts) ─────────────────
const sessionSecret = fs.existsSync(SECRET_FILE)
  ? fs.readFileSync(SECRET_FILE, 'utf8').trim()
  : (() => {
      const s = crypto.randomBytes(32).toString('hex');
      fs.writeFileSync(SECRET_FILE, s);
      return s;
    })();

// ── JSON persistence ───────────────────────────────────────────────────────────
function loadJSON(file, defaults) {
  // Clean up any orphaned .tmp left by a previous crash
  try { if (fs.existsSync(file + '.tmp')) fs.unlinkSync(file + '.tmp'); } catch {}

  if (!fs.existsSync(file)) return defaults;
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
  catch {
    // File exists but is corrupted — try the last-known-good backup before
    // falling back to defaults (which would wipe all users and reset passwords).
    const bak = file + '.bak';
    if (fs.existsSync(bak)) {
      try {
        const data = JSON.parse(fs.readFileSync(bak, 'utf8'));
        console.error(`[startup] ${path.basename(file)} corrupted — restored from .bak`);
        fs.writeFileSync(file, JSON.stringify(data, null, 2));
        return data;
      } catch {}
    }
    console.error(`[startup] ${path.basename(file)} corrupted and no .bak available — starting fresh`);
    return defaults;
  }
}

function saveJSON(file, data) {
  // Atomic write: write to .tmp first, then rename over the real file.
  // This guarantees the file is always complete — a killed process can never
  // leave a half-written (zero-byte or truncated) file that wipes user data.
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2));
  // Keep a backup of the previous good copy for corruption recovery.
  if (fs.existsSync(file)) {
    try { fs.copyFileSync(file, file + '.bak'); } catch {}
  }
  fs.renameSync(tmp, file);
}

let { tasks, nextIds } = (() => {
  const data = loadJSON(TASKS_FILE, { tasks: [], nextIds: {} });
  // Migrate old single-counter format
  if (data.nextId !== undefined && !data.nextIds) {
    data.nextIds = {};
    data.tasks.forEach(t => {
      if (t.userId) data.nextIds[t.userId] = Math.max(data.nextIds[t.userId] || 0, t.id) + 1;
    });
    delete data.nextId;
  }
  return data;
})();
function saveTasks() { saveJSON(TASKS_FILE, { tasks, nextIds }); }

let users = loadJSON(USERS_FILE, []);
function saveUsers() { saveJSON(USERS_FILE, users); }

// ── Bootstrap default admin on first run ───────────────────────────────────────
if (!users.find(u => u.isAdmin)) {
  users.push({
    username: 'admin',
    passwordHash: bcrypt.hashSync('admin123', 10),
    isAdmin: true,
    mustChangePassword: false,
    name: '', email: '', phone: ''
  });
  saveUsers();
  console.log('\n  Default admin created — username: admin  password: admin123\n');
}

// ── Migrate users missing profile fields ───────────────────────────────────────
let profileMigrated = false;
users.forEach(u => {
  if (u.name  === undefined) { u.name  = ''; profileMigrated = true; }
  if (u.email === undefined) { u.email = ''; profileMigrated = true; }
  if (u.phone === undefined) { u.phone = ''; profileMigrated = true; }
});
if (profileMigrated) saveUsers();

// ── Migrate legacy tasks (no userId) → assign to admin ────────────────────────
let migrated = false;
tasks.forEach(t => { if (!t.userId) { t.userId = 'admin'; migrated = true; } });
if (migrated) saveTasks();

// ── Storage limit ──────────────────────────────────────────────────────────────
const STORAGE_LIMIT_BYTES = 200 * 1024 * 1024; // 200 MB
const DISPLAY_MAX = 1000;

function getUserUsage(username) {
  const userTasks = tasks.filter(t => t.userId === username);
  const usedBytes = Buffer.byteLength(JSON.stringify(userTasks), 'utf8');
  return {
    taskCount:    userTasks.length,
    usedBytes,
    limitReached: usedBytes >= STORAGE_LIMIT_BYTES,
    displayMax:   DISPLAY_MAX
  };
}

// ── Helpers ────────────────────────────────────────────────────────────────────
const findUser = username => users.find(u => u.username === username);

function today() { return new Date().toISOString().slice(0, 10); }

function isValidDate(str) {
  return /^\d{4}-\d{2}-\d{2}$/.test(str) && !isNaN(Date.parse(str));
}

function daysBetween(from, to) {
  return Math.floor((Date.parse(to) - Date.parse(from)) / 86400000);
}

function enrichTask(t) {
  const daysPassed = daysBetween(t.date, today());
  const totalDays  = t.completionDate ? daysBetween(t.date, t.completionDate) : null;
  return { ...t, daysPassed, totalDays };
}

// ── Middleware ─────────────────────────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 8 * 60 * 60 * 1000 }
}));

function requireAuth(req, res, next) {
  if (!req.session.username) return res.redirect('/login');
  if (req.session.mustChangePassword) return res.redirect('/change-password');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.username) return res.redirect('/login');
  if (req.session.mustChangePassword) return res.redirect('/change-password');
  if (!findUser(req.session.username)?.isAdmin) return res.redirect('/');
  next();
}

function apiAuth(req, res, next) {
  if (!req.session.username) return res.status(401).json({ error: 'Not authenticated' });
  if (req.session.mustChangePassword) return res.status(403).json({ error: 'Password change required' });
  next();
}

function adminApiAuth(req, res, next) {
  if (!req.session.username) return res.status(401).json({ error: 'Not authenticated' });
  if (!findUser(req.session.username)?.isAdmin) return res.status(403).json({ error: 'Admin access required' });
  next();
}

// ── Page routes ────────────────────────────────────────────────────────────────
app.get('/', requireAuth, (req, res) => res.sendFile(path.join(VIEWS, 'app.html')));

app.get('/login', (req, res) => {
  if (req.session.username && !req.session.mustChangePassword) return res.redirect('/');
  res.sendFile(path.join(VIEWS, 'login.html'));
});

app.get('/change-password', (req, res) => {
  if (!req.session.username) return res.redirect('/login');
  res.sendFile(path.join(VIEWS, 'change-password.html'));
});

app.get('/admin', requireAdmin, (req, res) => res.sendFile(path.join(VIEWS, 'admin.html')));
app.get('/profile', requireAuth, (req, res) => res.sendFile(path.join(VIEWS, 'profile.html')));

// ── Auth API ───────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = findUser(username);
  if (!user || !bcrypt.compareSync(password, user.passwordHash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }
  req.session.username = user.username;
  req.session.mustChangePassword = user.mustChangePassword;
  res.json({ username: user.username, mustChangePassword: user.mustChangePassword, isAdmin: !!user.isAdmin });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.post('/api/change-password', (req, res) => {
  if (!req.session.username) return res.status(401).json({ error: 'Not authenticated' });
  const { currentPassword, newPassword } = req.body;
  const user = findUser(req.session.username);

  if (!bcrypt.compareSync(currentPassword, user.passwordHash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  if (currentPassword === newPassword) {
    return res.status(400).json({ error: 'New password must differ from current password' });
  }

  user.passwordHash = bcrypt.hashSync(newPassword, 10);
  user.mustChangePassword = false;
  saveUsers();
  req.session.mustChangePassword = false;
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.username) return res.status(401).json({ error: 'Not authenticated' });
  const user = findUser(req.session.username);
  res.json({ username: user.username, isAdmin: !!user.isAdmin, name: user.name || '', email: user.email || '', phone: user.phone || '' });
});

app.put('/api/me', apiAuth, (req, res) => {
  const user = findUser(req.session.username);
  user.name  = ((req.body.name  || '').trim()).slice(0, 100);
  user.email = ((req.body.email || '').trim()).slice(0, 100);
  user.phone = ((req.body.phone || '').trim()).slice(0, 30);
  saveUsers();
  res.json({ ok: true, name: user.name, email: user.email, phone: user.phone });
});

// ── Admin API ──────────────────────────────────────────────────────────────────
app.get('/admin/api/users', adminApiAuth, (req, res) => {
  res.json(users.map(u => ({
    username: u.username,
    isAdmin: !!u.isAdmin,
    mustChangePassword: u.mustChangePassword,
    taskCount: tasks.filter(t => t.userId === u.username).length
  })));
});

app.post('/admin/api/users', adminApiAuth, (req, res) => {
  const { username, password, name, email, phone } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password are required' });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: 'Username: 3–20 chars, letters/numbers/underscores only' });
  }
  if (findUser(username)) return res.status(409).json({ error: `Username "${username}" already exists` });

  users.push({
    username,
    passwordHash: bcrypt.hashSync(password, 10),
    isAdmin: false,
    mustChangePassword: true,
    name:  ((name  || '').trim()).slice(0, 100),
    email: ((email || '').trim()).slice(0, 100),
    phone: ((phone || '').trim()).slice(0, 30)
  });
  saveUsers();
  res.status(201).json({ username, mustChangePassword: true });
});

app.delete('/admin/api/users/:username', adminApiAuth, (req, res) => {
  const { username } = req.params;
  if (username === req.session.username) return res.status(400).json({ error: 'Cannot delete your own account' });
  const index = users.findIndex(u => u.username === username);
  if (index === -1) return res.status(404).json({ error: 'User not found' });
  users.splice(index, 1);
  tasks = tasks.filter(t => t.userId !== username);
  saveUsers();
  saveTasks();
  res.status(204).send();
});

// ── Tasks API ──────────────────────────────────────────────────────────────────
app.get('/api/tasks', apiAuth, (req, res) => {
  res.json(tasks.filter(t => t.userId === req.session.username).map(enrichTask));
});

app.get('/api/usage', apiAuth, (req, res) => {
  res.json(getUserUsage(req.session.username));
});

app.post('/api/tasks', apiAuth, (req, res) => {
  const { name, date, completionDate } = req.body;
  if (!name) return res.status(400).json({ error: 'name is required' });

  const usage = getUserUsage(req.session.username);
  if (usage.limitReached) {
    return res.status(413).json({
      error: `Storage limit reached (${usage.taskCount} / ~${DISPLAY_MAX} tasks). Delete old tasks to add new ones.`
    });
  }

  const taskDate = date || today();
  if (!isValidDate(taskDate)) return res.status(400).json({ error: 'date must be YYYY-MM-DD' });
  if (completionDate && !isValidDate(completionDate)) return res.status(400).json({ error: 'completionDate must be YYYY-MM-DD' });
  if (completionDate && completionDate < taskDate) return res.status(400).json({ error: 'completionDate cannot be before date' });

  const username = req.session.username;
  if (!nextIds[username]) nextIds[username] = 1;
  const task = { id: nextIds[username]++, userId: username, name, date: taskDate, completionDate: completionDate || null };
  tasks.push(task);
  saveTasks();
  res.status(201).json(enrichTask(task));
});

app.get('/api/tasks/date/:date', apiAuth, (req, res) => {
  const { date } = req.params;
  if (!isValidDate(date)) return res.status(400).json({ error: 'date must be YYYY-MM-DD' });
  res.json(tasks.filter(t => t.userId === req.session.username && t.date === date).map(enrichTask));
});

app.delete('/api/tasks/:id', apiAuth, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const index = tasks.findIndex(t => t.id === id && t.userId === req.session.username);
  if (index === -1) return res.status(404).json({ error: 'Task not found' });
  tasks.splice(index, 1);
  saveTasks();
  res.status(204).send();
});

app.listen(PORT, () => console.log(`To-Do Tracker running at http://localhost:${PORT}`));
