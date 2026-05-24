 // server.js
const express  = require('express');
const mongoose = require('mongoose');
const cors     = require('cors');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
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

// ─── SCHEMAS ──────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true, uppercase: true },
  password:  { type: String, required: true },
  role:      { type: String, enum: ['admin', 'staff'], default: 'staff' },
  name:      { type: String, default: '' },
  createdAt: { type: Date, default: Date.now },
});
const User = mongoose.model('User', userSchema);

const noticeSchema = new mongoose.Schema({
  title:          { type: String, required: true },
  content:        { type: String, required: true },
  priority:       { type: String, enum: ['normal', 'high', 'urgent'], default: 'normal' },
  isAnnouncement: { type: Boolean, default: false },
  createdBy:      { type: String, default: 'ADMIN' },
  createdAt:      { type: Date, default: Date.now },
});
const Notice = mongoose.model('Notice', noticeSchema);

// ─── ATTENDANCE SCHEMA ────────────────────────────────────────────────────────
// Supports BOTH the old staff system (employeeId/checkIn as string)
// AND the new admin system (staffId/checkIn as Date).
// We unify on staffId + date as the unique key.
const attendanceSchema = new mongoose.Schema({
  // Identity — use staffId everywhere; employeeId is a legacy alias
  staffId:            { type: String, required: true },   // "E01", "PAWAN", etc.
  employeeName:       { type: String, default: '' },
  department:         { type: String, default: '' },
  date:               { type: String, required: true },   // "YYYY-MM-DD"

  // Times stored as Date objects
  checkIn:            { type: Date },
  checkOut:           { type: Date },

  // Formatted strings for staff display (HH:MM)
  checkInDisplay:     { type: String },
  checkOutDisplay:    { type: String },

  status:             { type: String, enum: ['Present', 'Absent', 'Checked In', 'Early', 'Late'], default: 'Present' },
  hoursWorked:        { type: Number },
  locationName:       { type: String },
  locationPlaceName:  { type: String },
  location:           { type: mongoose.Schema.Types.Mixed },   // { lat, lng, accuracy }
  distanceFromOffice: { type: Number },
  workDescription:    { type: String },
  note:               { type: String },
  recordedBy:         { type: String, default: 'staff' },      // 'staff' | 'admin'
}, { timestamps: true });

// One record per staff per day
attendanceSchema.index({ staffId: 1, date: 1 }, { unique: true });
const Attendance = mongoose.model('Attendance', attendanceSchema);

// ─── JWT + MIDDLEWARE ─────────────────────────────────────────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'dolakha_census_secret_2083';

// ⚠️  THIS IS THE KEY FIX: was called "authenticateToken" in the broken routes
//     but only "auth" was defined. Now everything uses "auth".
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

// ─── SEED ADMIN ───────────────────────────────────────────────────────────────
async function seedAdmin() {
  const exists = await User.findOne({ username: 'PAWAN' });
  if (!exists) {
    const hash = await bcrypt.hash('8586', 10);
    await User.create({ username: 'PAWAN', password: hash, role: 'admin', name: 'Pawan' });
    console.log('🌱 Default admin PAWAN seeded');
  }
}
seedAdmin();

// ═══════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/health', (req, res) => res.json({ ok: true }));

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
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/create-staff', auth, adminOnly, async (req, res) => {
  try {
    const { username, password, name } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Username and password required' });

    const finalUsername = username.toUpperCase();
    if (await User.findOne({ username: finalUsername }))
      return res.status(409).json({ error: 'Username already exists' });

    const hash = await bcrypt.hash(password, 10);
    const user = await User.create({ username: finalUsername, password: hash, role: 'staff', name: name || finalUsername });
    res.json({ message: 'Staff account created', username: user.username });
  } catch {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/staff-list', auth, adminOnly, async (req, res) => {
  const staff = await User.find({ role: 'staff' }, 'username name createdAt');
  res.json(staff);
});

app.delete('/api/staff/:staffId', auth, adminOnly, async (req, res) => {
  try {
    await User.deleteOne({ username: req.params.staffId.toUpperCase() });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/me', auth, (req, res) => res.json(req.user));

// ═══════════════════════════════════════════════════════════════════════════════
// NOTICE ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

app.get('/api/notices', auth, async (req, res) => {
  try {
    const notices = await Notice.find().sort({ createdAt: -1 }).limit(50);
    res.json(notices);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/notices', auth, async (req, res) => {
  try {
    const notice = await Notice.create({
      title:          req.body.title,
      content:        req.body.content,
      priority:       req.body.priority || 'normal',
      isAnnouncement: req.body.isAnnouncement || false,
      createdBy:      req.user?.username || 'ADMIN',
    });
    res.status(201).json(notice);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/notices/:id', auth, async (req, res) => {
  try {
    await Notice.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ═══════════════════════════════════════════════════════════════════════════════
// ATTENDANCE ROUTES
// ═══════════════════════════════════════════════════════════════════════════════

// ── Helper: format Date → "HH:MM" in NPT (UTC+5:45) ─────────────────────────
function toNPTDisplay(dateObj) {
  if (!dateObj) return null;
  const npt = new Date(dateObj.getTime() + (5 * 60 + 45) * 60000);
  return `${String(npt.getUTCHours()).padStart(2, '0')}:${String(npt.getUTCMinutes()).padStart(2, '0')}`;
}

// ── Serialize record for staff portal ────────────────────────────────────────
function serializeForStaff(r) {
  return {
    _id:              r._id,
    date:             r.date,
    staffId:          r.staffId,
    employeeId:       r.staffId,          // alias for old Attendance.jsx
    employeeName:     r.employeeName,
    department:       r.department,
    // Display times as "HH:MM" strings (NPT) — what Attendance.jsx renders
    checkIn:          r.checkIn  ? (r.checkInDisplay  || toNPTDisplay(r.checkIn))  : null,
    checkOut:         r.checkOut ? (r.checkOutDisplay || toNPTDisplay(r.checkOut)) : null,
    status:           r.status,
    hoursWorked:      r.hoursWorked,
    locationName:     r.locationName || r.locationPlaceName,
    locationPlaceName:r.locationPlaceName || r.locationName,
    location:         r.location,
    workDescription:  r.workDescription,
    note:             r.note,
    recordedBy:       r.recordedBy,
  };
}

// ── 1. STAFF CHECK-IN ─────────────────────────────────────────────────────────
//    POST /api/attendance/mark   (called by Attendance.jsx)
app.post('/api/attendance/mark', auth, async (req, res) => {
  try {
    const { attendanceType, workDescription, location, locationPlaceName } = req.body;
    const staffId = req.user.username;
    const now     = new Date();
    // Date in NPT
    const npt     = new Date(now.getTime() + (5 * 60 + 45) * 60000);
    const date    = npt.toISOString().split('T')[0];
    const display = `${String(npt.getUTCHours()).padStart(2,'0')}:${String(npt.getUTCMinutes()).padStart(2,'0')}`;

    let record = await Attendance.findOne({ staffId, date });

    if (attendanceType === 'checkin') {
      if (record && record.checkIn)
        return res.json({ success: false, error: 'Already checked in today' });

      const update = {
        staffId,
        employeeName: req.user.name || req.user.username,
        date,
        checkIn:         now,
        checkInDisplay:  display,
        status:          'Checked In',
        workDescription: workDescription || '',
        locationPlaceName,
        location,
        locationName:    locationPlaceName,
        recordedBy:      'staff',
      };

      record = await Attendance.findOneAndUpdate(
        { staffId, date },
        { $set: update },
        { upsert: true, new: true, setDefaultsOnInsert: true }
      );
      return res.json({ success: true, data: serializeForStaff(record) });
    }

    if (attendanceType === 'checkout') {
      if (!record || !record.checkIn)
        return res.json({ success: false, error: 'No check-in found for today' });
      if (record.checkOut)
        return res.json({ success: false, error: 'Already checked out today' });

      const diff = (now - record.checkIn) / 3600000;
      record.checkOut        = now;
      record.checkOutDisplay = display;
      record.status          = 'Present';
      record.hoursWorked     = Math.round(diff * 10) / 10;
      record.workDescription = workDescription || record.workDescription;
      await record.save();
      return res.json({ success: true, data: serializeForStaff(record) });
    }

    res.status(400).json({ success: false, error: 'Invalid attendanceType' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── 2. GET MY RECORDS ─────────────────────────────────────────────────────────
//    GET /api/attendance/:staffId   (called by Attendance.jsx fetchMyRecords)
app.get('/api/attendance/:staffId', auth, async (req, res) => {
  try {
    // Staff can only see their own; admin can see anyone
    const requestedId = req.params.staffId.toUpperCase();
    if (req.user.role !== 'admin' && req.user.username !== requestedId)
      return res.status(403).json({ success: false, error: 'Forbidden' });

    const records = await Attendance.find({ staffId: requestedId })
      .sort({ date: -1 })
      .limit(60);

    res.json({ success: true, data: records.map(serializeForStaff) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── 3. GET DAILY SHEET ────────────────────────────────────────────────────────
//    GET /api/attendance/date/:date   (called by Attendance.jsx fetchDailyRecords)
app.get('/api/attendance/date/:date', auth, async (req, res) => {
  try {
    const records = await Attendance.find({ date: req.params.date }).sort({ staffId: 1 });
    res.json({ success: true, data: records.map(serializeForStaff) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── 4. GET SUMMARY RANGE ──────────────────────────────────────────────────────
//    GET /api/attendance/summary/range?from=YYYY-MM-DD&to=YYYY-MM-DD
app.get('/api/attendance/summary/range', auth, async (req, res) => {
  try {
    const { from, to } = req.query;
    const records = await Attendance.find({
      date: { $gte: from, $lte: to },
    }).sort({ date: 1, staffId: 1 });
    res.json({ success: true, data: records.map(serializeForStaff) });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ── 5. ADMIN: GET with filters (used by Admin.jsx) ───────────────────────────
//    GET /api/attendance?date=&month=&staffId=&limit=
app.get('/api/attendance', auth, async (req, res) => {
  try {
    const { date, month, staffId, limit } = req.query;
    const filter = {};

    // Staff can only query their own records
    if (req.user.role !== 'admin') {
      filter.staffId = req.user.username;
    } else if (staffId) {
      filter.staffId = staffId;
    }

    if (date)       filter.date = date;
    else if (month) filter.date = { $regex: `^${month}` };

    let query = Attendance.find(filter).sort({ date: -1, createdAt: -1 });
    if (limit) query = query.limit(parseInt(limit));

    const records = await query.exec();
    res.json(records); // Admin.jsx expects a plain array
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── 6. ADMIN: MANUAL ENTRY (upsert) ─────────────────────────────────────────
//    POST /api/attendance/manual
app.post('/api/attendance/manual', auth, async (req, res) => {
  try {
    const { staffId, date, checkIn, checkOut, status, note } = req.body;
    if (!staffId || !date)
      return res.status(400).json({ error: 'staffId and date are required' });

    const update = {
      status:     status || 'Present',
      note:       note || '',
      recordedBy: 'admin',
    };

    if (checkIn) {
      update.checkIn        = new Date(checkIn);
      update.checkInDisplay = toNPTDisplay(new Date(checkIn));
    }
    if (checkOut) {
      update.checkOut        = new Date(checkOut);
      update.checkOutDisplay = toNPTDisplay(new Date(checkOut));
    }
    if (checkIn && checkOut) {
      const diff = (new Date(checkOut) - new Date(checkIn)) / 3600000;
      update.hoursWorked = Math.round(diff * 10) / 10;
    }

    const record = await Attendance.findOneAndUpdate(
      { staffId, date },
      { $set: update },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );
    res.status(200).json(record);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── 7. ADMIN: PATCH existing record ──────────────────────────────────────────
//    PATCH /api/attendance/:id
app.patch('/api/attendance/:id', auth, async (req, res) => {
  try {
    const update = { ...req.body, recordedBy: 'admin' };

    if (req.body.checkIn) {
      update.checkIn        = new Date(req.body.checkIn);
      update.checkInDisplay = toNPTDisplay(new Date(req.body.checkIn));
    }
    if (req.body.checkOut) {
      update.checkOut        = new Date(req.body.checkOut);
      update.checkOutDisplay = toNPTDisplay(new Date(req.body.checkOut));
    }
    if (update.checkIn && update.checkOut) {
      const diff = (new Date(update.checkOut) - new Date(update.checkIn)) / 3600000;
      update.hoursWorked = Math.round(diff * 10) / 10;
    }

    const record = await Attendance.findByIdAndUpdate(
      req.params.id,
      { $set: update },
      { new: true }
    );
    if (!record) return res.status(404).json({ error: 'Record not found' });
    res.json(record);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── 8. DELETE attendance record ───────────────────────────────────────────────
//    DELETE /api/attendance/:id
app.delete('/api/attendance/:id', auth, async (req, res) => {
  try {
    await Attendance.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── 9. Archive & delete whole month ─────────────────────────────────────────
//    DELETE /api/attendance/archive-delete?month=YYYY-MM
app.delete('/api/attendance/archive-delete', auth, adminOnly, async (req, res) => {
  try {
    const { month } = req.query;
    if (!month) return res.status(400).json({ error: 'month required' });
    const result = await Attendance.deleteMany({ date: { $regex: `^${month}` } });
    res.json({ success: true, deleted: result.deletedCount });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── 10. Contact admin (missed check-in request) ──────────────────────────────
//    POST /api/attendance/contact-admin
app.post('/api/attendance/contact-admin', auth, async (req, res) => {
  try {
    const { employeeId, employeeName, date, message } = req.body;
    // Save as a notice so admin can see it
    await Notice.create({
      title:     `📨 Attendance Request — ${employeeId}`,
      content:   `${employeeName} (${employeeId}) missed check-in on ${date}.\n\nMessage: ${message}`,
      priority:  'high',
      createdBy: employeeId,
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// ═══════════════════════════════════════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════════════════════════════════════
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));