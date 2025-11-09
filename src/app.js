require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

const app = express();

app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true
}));

mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/geo-fenced-notifications', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB connected')).catch(err => console.error('MongoDB error:', err));

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  name: String,
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  locationConsent: { type: Boolean, default: false },
  pushConsent: { type: Boolean, default: false },
  preciseLocation: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

userSchema.methods.comparePassword = async function(password) {
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model('User', userSchema);

const geoFenceSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  type: { type: String, enum: ['circle', 'polygon'], default: 'circle' },
  center: { lat: Number, lng: Number },
  radius: { type: Number, default: 100 },
  coordinates: [{ lat: Number, lng: Number }],
  activationWindow: { start: String, end: String },
  daysActive: [String],
  priority: { type: Number, default: 1 },
  targetUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  enterMessage: String,
  exitMessage: String,
  hysteresisMeters: { type: Number, default: 10 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  createdAt: { type: Date, default: Date.now },
  updatedAt: Date
});

const GeoFence = mongoose.model('GeoFence', geoFenceSchema);

const subscriptionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  deviceId: { type: String, required: true },
  pushSubscription: {
    endpoint: String,
    keys: { p256dh: String, auth: String }
  },
  isActive: { type: Boolean, default: true },
  lastPingAt: Date,
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, default: () => new Date(+new Date() + 30*24*60*60*1000) }
});

const UserSubscription = mongoose.model('UserSubscription', subscriptionSchema);

const eventSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  fenceId: { type: mongoose.Schema.Types.ObjectId, ref: 'GeoFence', required: true },
  eventType: { type: String, enum: ['enter', 'exit', 'boundary_flap', 'accuracy_issue'] },
  location: { lat: Number, lng: Number },
  accuracy: Number,
  notificationSent: { type: Boolean, default: false },
  notificationId: String,
  correlationId: String,
  metadata: { speed: Number, heading: Number, timestamp: Date },
  createdAt: { type: Date, default: Date.now, expires: 2592000 }
});

const EventHistory = mongoose.model('EventHistory', eventSchema);

function calculateDistance(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const φ1 = (lat1 * Math.PI) / 180;
  const φ2 = (lat2 * Math.PI) / 180;
  const Δφ = ((lat2 - lat1) * Math.PI) / 180;
  const Δλ = ((lng2 - lng1) * Math.PI) / 180;
  const a = Math.sin(Δφ / 2) * Math.sin(Δφ / 2) +
            Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) * Math.sin(Δλ / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function isPointInCircle(lat, lng, centerLat, centerLng, radius) {
  const distance = calculateDistance(lat, lng, centerLat, centerLng);
  return distance <= radius;
}

function isPointInPolygon(lat, lng, polygon) {
  let isInside = false;
  for (let i = 0, j = polygon.length - 1; i < polygon.length; j = i++) {
    const xi = polygon[i].lng, yi = polygon[i].lat;
    const xj = polygon[j].lng, yj = polygon[j].lat;
    const intersect = ((yi > lng) !== (yj > lng)) &&
                      (lat < (xj - xi) * (lng - yi) / (yj - yi) + xi);
    if (intersect) isInside = !isInside;
  }
  return isInside;
}

function isPointInFence(lat, lng, fence) {
  if (fence.type === 'circle') {
    return isPointInCircle(lat, lng, fence.center.lat, fence.center.lng, fence.radius);
  } else if (fence.type === 'polygon') {
    return isPointInPolygon(lat, lng, fence.coordinates);
  }
  return false;
}

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    req.userId = decoded.userId;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ error: 'User exists' });
    const user = new User({ email, password, name });
    await user.save();
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your-secret-key');
    res.json({ token, user: { id: user._id, email: user.email, name: user.name } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user || !(await user.comparePassword(password))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET || 'your-secret-key');
    res.json({ token, user: { id: user._id, email: user.email, name: user.name, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/fences', authMiddleware, async (req, res) => {
  try {
    const fence = new GeoFence({ ...req.body, createdBy: req.userId });
    await fence.save();
    res.json(fence);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/fences', authMiddleware, async (req, res) => {
  try {
    const fences = await GeoFence.find({ $or: [{ createdBy: req.userId }, { targetUsers: req.userId }] });
    res.json(fences);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/fences/:id', authMiddleware, async (req, res) => {
  try {
    const fence = await GeoFence.findByIdAndUpdate(req.params.id, { ...req.body, updatedAt: Date.now() }, { new: true });
    res.json(fence);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/fences/:id', authMiddleware, async (req, res) => {
  try {
    await GeoFence.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/locations/ping', authMiddleware, async (req, res) => {
  try {
    const { lat, lng, accuracy, timestamp } = req.body;
    const correlationId = uuidv4();
    const fences = await GeoFence.find({ $or: [{ createdBy: req.userId }, { targetUsers: req.userId }] });
    const transitions = [];
    for (const fence of fences) {
      const isInside = isPointInFence(lat, lng, fence);
      const lastEvent = await EventHistory.findOne({ userId: req.userId, fenceId: fence._id }).sort({ createdAt: -1 });
      const wasInside = lastEvent && lastEvent.eventType === 'enter' && lastEvent.eventType !== 'exit';
      let eventType = null;
      if (!wasInside && isInside) eventType = 'enter';
      else if (wasInside && !isInside) eventType = 'exit';
      if (eventType) {
        const event = new EventHistory({
          userId: req.userId,
          fenceId: fence._id,
          eventType,
          location: { lat, lng },
          accuracy,
          correlationId,
          metadata: { timestamp }
        });
        await event.save();
        transitions.push({ fenceId: fence._id, eventType, message: eventType === 'enter' ? fence.enterMessage : fence.exitMessage });
      }
    }
    res.json({ success: true, transitions, correlationId });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/subscriptions/subscribe', authMiddleware, async (req, res) => {
  try {
    const { pushSubscription, deviceId } = req.body;
    const subscription = new UserSubscription({ userId: req.userId, deviceId, pushSubscription });
    await subscription.save();
    res.json({ success: true, subscriptionId: subscription._id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put('/api/users/preferences', authMiddleware, async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(req.userId, req.body, { new: true });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/events', authMiddleware, async (req, res) => {
  try {
    const events = await EventHistory.find({ userId: req.userId }).sort({ createdAt: -1 }).limit(50).populate('fenceId');
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date() });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Geo-Fenced Notifications Backend running on port ${PORT}`);
});