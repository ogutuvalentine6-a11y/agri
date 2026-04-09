const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');
require('dotenv').config();

const app = express();

// 1. Critical Environment Check
const requiredEnv = ['MONGODB_URI', 'JWT_SECRET', 'REFRESH_TOKEN_SECRET'];
requiredEnv.forEach(key => {
    if (!process.env[key]) {
        console.error(`CRITICAL ERROR: ${key} is not defined in environment variables.`);
        process.exit(1);
    }
});

// 2. Middleware
app.use(helmet({
    contentSecurityPolicy: false, // Set to false if loading external fonts/scripts easily
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['http://localhost:3000'],
  credentials: true
}));

app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// 3. Static Files (Improved for Vercel)
// This serves everything from a 'public' folder at the root
app.use(express.static(path.join(__dirname, '../public')));

// 4. Rate Limiting (Applied to API only)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { status: 'error', message: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// 5. Database Connection
let isConnected = false;
async function connectToDatabase() {
  if (isConnected) return;
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    isConnected = true;
    console.log("Connected to MongoDB");
  } catch (error) {
    console.error('Database connection error:', error);
  }
}

// 6. Token Verification Helper (Refactored)
const verifyToken = (token, secret) => {
    try {
        return jwt.verify(token, secret);
    } catch (err) {
        return { error: err.name }; // Returns specific error type (e.g., TokenExpiredError)
    }
};

// --- ROUTES ---

// Example Weather API Route
app.get('/api/weather', async (req, res) => {
  try {
    // In production, fetch from a real API like OpenWeather
    res.json({
      temp: 24,
      description: 'Partly Cloudy',
      humidity: 72,
      forecast: [
        { day: 'Mon', high: 27, low: 18, icon: '☀️' },
        { day: 'Tue', high: 20, low: 15, icon: '🌧️' }
      ]
    });
  } catch (error) {
    res.status(500).json({ message: "Server error fetching weather" });
  }
});

// Catch-all for Frontend (SPA Mode)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// Export for Vercel
module.exports = app;

// Local development listener
if (require.main === module) {
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        connectToDatabase();
        console.log(`Server running on port ${PORT}`);
    });
}
