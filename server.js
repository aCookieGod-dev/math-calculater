const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const path = require('path');

const app = express();
app.use(express.json());
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const MONGO_URI = process.env.MONGODB_URI;
if (!MONGO_URI) {
  console.error('❌ MONGODB_URI not set');
  process.exit(1);
}

mongoose.connect(MONGO_URI)
  .then(() => console.log('✓ MongoDB connected'))
  .catch(err => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });

/* ---------- Models ---------- */

const UserSchema = new mongoose.Schema({
  username:  { type: String, required: true, unique: true, index: true },
  password:  { type: String, required: true },
  bestCO2:   { type: Number, default: null, index: true },
  createdAt: { type: Date, default: Date.now }
});

const SessionSchema = new mongoose.Schema({
  token:     { type: String, required: true, unique: true, index: true },
  username:  { type: String, required: true },
  expiresAt: { type: Date, required: true, index: { expires: 0 } }
});

const User    = mongoose.model('User', UserSchema);
const Session = mongoose.model('Session', SessionSchema);

const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const mkToken = () => crypto.randomBytes(32).toString('hex');

/* ---------- Auth ---------- */

app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Please fill all fields' });
    if (username.length < 3 || username.length > 20) return res.status(400).json({ error: 'Username must be 3-20 characters' });
    if (password.length < 4) return res.status(400).json({ error: 'Password must be at least 4 characters' });
    if (!/^[a-zA-Z0-9_\u4e00-\u9fa5]+$/.test(username)) return res.status(400).json({ error: 'Username can only contain letters, numbers, underscore, Chinese' });
    if (await User.exists({ username })) return res.status(409).json({ error: 'Username already taken' });

    const hash = await bcrypt.hash(password, 10);
    await User.create({ username, password: hash });

    const token = mkToken();
    await Session.create({ token, username, expiresAt: new Date(Date.now() + TOKEN_TTL_MS) });

    res.json({ token, username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'Please fill all fields' });

    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password)))
      return res.status(401).json({ error: 'Invalid username or password' });

    const token = mkToken();
    await Session.create({ token, username, expiresAt: new Date(Date.now() + TOKEN_TTL_MS) });

    res.json({ token, username });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

async function auth(req, res, next) {
  try {
    const h = req.headers.authorization || '';
    const token = h.startsWith('Bearer ') ? h.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Not logged in' });

    const session = await Session.findOne({ token });
    if (!session) return res.status(401).json({ error: 'Session expired' });

    req.username = session.username;
    req.token = token;
    next();
  } catch (e) {
    res.status(500).json({ error: 'Server error' });
  }
}

app.post('/api/logout', auth, async (req, res) => {
  await Session.deleteOne({ token: req.token });
  res.json({ ok: true });
});

app.get('/api/me', auth, async (req, res) => {
  const user = await User.findOne({ username: req.username });
  res.json({ username: user.username, bestCO2: user.bestCO2 });
});

/* ---------- Score ---------- */

app.post('/api/score', auth, async (req, res) => {
  try {
    const { co2 } = req.body || {};
    if (typeof co2 !== 'number' || !isFinite(co2) || co2 <= 0)
      return res.status(400).json({ error: 'Invalid score' });

    const rounded = Math.round(co2 * 100) / 100;
    const user = await User.findOne({ username: req.username });

    const newBest = user.bestCO2 === null || rounded < user.bestCO2;
    if (newBest) {
      user.bestCO2 = rounded;
      await user.save();
    }

    res.json({ ok: true, newBest, best: user.bestCO2 });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- Leaderboard ---------- */

app.get('/api/leaderboard', async (req, res) => {
  try {
    const users = await User.find(
      { bestCO2: { $ne: null } },
      { username: 1, bestCO2: 1 }
    ).sort({ bestCO2: 1 }).limit(20).lean();

    res.json(users.map(u => ({ username: u.username, co2: u.bestCO2 })));
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error' });
  }
});

/* ---------- 404 ---------- */

app.use((req, res) => res.status(404).send('Not found'));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`✓ http://localhost:${PORT}`));