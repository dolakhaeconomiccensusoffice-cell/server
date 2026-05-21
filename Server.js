// server.js
// Run: node server.js
// Install: npm install express mongoose cors bcryptjs jsonwebtoken dotenv

const express    = require('express');
const mongoose   = require('mongoose');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// ─── MONGO CONNECTION ─────────────────────────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI ||
  'mongodb+srv://admin:admin000@cluster0.0vmsyu6.mongodb.net/census?appName=Cluster0';

mongoose.connect(MONGO_URI)
  .then(() => console.log('✅ MongoDB Atlas connected'))
  .catch(err => console.error('❌ MongoDB error:', err));

// ─── USER SCHEMA ──────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true, uppercase: true },
  password:  { type: String, required: true },   // bcrypt hash
  role:      { type: String, enum: ['admin', 'staff'], default: 'staff' },
  name:      { type: String, default: '' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// ─── JWT SECRET ───────────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'dolakha_census_secret_2083';

// ─── SEED ADMIN (runs once if no admin exists) ────────────────────────────────
async function seedAdmin() {
  const exists = await User.findOne({ username: 'PAWAN' });
  if (!exists) {
    const hash = await bcrypt.hash('8586', 10);
    await User.create({ username: 'PAWAN', password: hash, role: 'admin', name: 'Pawan' });
    console.log('🌱 Default admin PAWAN seeded');
  }
}
seedAdmin();

// ─── MIDDLEWARE: verify JWT ────────────────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admins only' });
  next();
}

// ─── ROUTES ───────────────────────────────────────────────────────────────────

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password required' });

    const user = await User.findOne({ username: username.toUpperCase() });
    if (!user) return res.status(401).json({ error: 'Invalid username or password' });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid username or password' });

    const token = jwt.sign(
      { id: user._id, username: user.username, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({ token, user: { id: user.username, name: user.name, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/create-staff  (admin only)
app.post('/api/create-staff', auth, adminOnly, async (req, res) => {
  try {
    const { username, password, name } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password required' });

    const finalUsername = username.toUpperCase();
    const exists = await User.findOne({ username: finalUsername });
    if (exists) return res.status(409).json({ error: 'Username already exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({
      username: finalUsername,
      password: hash,
      role: 'staff',
      name: name || finalUsername
    });

    res.json({ message: 'Staff account created', username: user.username });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/staff-list  (admin only)
app.get('/api/staff-list', auth, adminOnly, async (req, res) => {
  const staff = await User.find({ role: 'staff' }, 'username name createdAt');
  res.json(staff);
});

// GET /api/me  — verify token & get current user
app.get('/api/me', auth, (req, res) => {
  res.json(req.user);
});

// ─── START ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));