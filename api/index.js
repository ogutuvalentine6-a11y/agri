const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();

// Security and Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({
  origin: ['https://agri-gamma-red.vercel.app', 'http://localhost:3000', 'http://127.0.0.1:5500'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// Rate limiting to prevent abuse
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// Serve static files from the "public" directory
app.use(express.static(path.join(__dirname, '../public')));

// Database Connection Logic
let isConnected = false;
async function connectToDatabase() {
  if (isConnected) return;
  try {
    if (!process.env.MONGODB_URI) throw new Error('MONGODB_URI is missing');
    await mongoose.connect(process.env.MONGODB_URI);
    isConnected = true;
    console.log("Connected to MongoDB");
  } catch (err) {
    console.error("DB Connection Error:", err);
  }
}

// Token Verification Utilities
const verifyAccessToken = (token) => {
  try { return jwt.verify(token, process.env.JWT_SECRET); } 
  catch (e) { return null; }
};

// --- API ROUTES ---

app.get('/api/health', (req, res) => res.json({ status: 'up' }));

app.get('/api/weather', async (req, res) => {
  await connectToDatabase();
  // Placeholder weather data
  res.json({
    temp: 24,
    description: 'Partly Cloudy',
    humidity: 72,
    forecast: [
      { day: 'Mon', high: 27, low: 18, icon: '☀️' },
      { day: 'Tue', high: 20, low: 15, icon: '🌧️' }
    ]
  });
});

// Admin Settings Route
app.put('/api/admin/settings', async (req, res) => {
  const token = req.cookies.accessToken;
  const user = verifyAccessToken(token);
  if (!user || user.role !== 'admin') return res.status(403).json({ message: 'Unauthorized' });
  
  // Logic to save settings to DB would go here
  res.json({ message: 'Settings updated successfully' });
});

// Catch-all: Send user to index.html for any non-API route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Export for Vercel
module.exports = app;

// Local Server Start
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`Server on port ${PORT}`));
}
