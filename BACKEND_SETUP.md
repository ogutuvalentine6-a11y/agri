# AgroNexus — Backend Architecture & Setup Guide

## Stack
- **Frontend**: index.html / user.html / admin.html (static, deployable to Vercel)
- **Backend**: Node.js + Express (Vercel Serverless Functions at `/api`)
- **Database**: MongoDB Atlas (encrypted at rest + TLS)
- **Auth**: JWT (RS256) + bcrypt(12) + httpOnly refresh tokens

---

## Vercel Environment Variables (NEVER put in code)

In your Vercel project → Settings → Environment Variables, add:

```
MONGODB_URI=mongodb+srv://user:pass@cluster.mongodb.net/agronexus?retryWrites=true&w=majority
JWT_PRIVATE_KEY=<your RS256 private key>
JWT_PUBLIC_KEY=<your RS256 public key>
REFRESH_TOKEN_SECRET=<random 64-char hex>
OPENWEATHER_API_KEY=<your openweathermap key>
NODE_ENV=production
```

---

## Backend File Structure (Vercel Serverless)

```
/api
  /auth
    login.js         → POST /api/auth/login
    register.js      → POST /api/auth/register
    refresh.js       → POST /api/auth/refresh
    logout.js        → POST /api/auth/logout
    forgot-password.js
  /users
    me.js            → GET /api/users/me
    stats.js         → GET /api/users/stats
    profile.js       → PUT /api/users/profile
    change-password.js → PUT /api/users/change-password
  /transactions
    index.js         → GET /api/transactions
    deposit.js       → POST /api/transactions/deposit
    withdraw.js      → POST /api/transactions/withdraw
  /admin
    stats.js         → GET /api/admin/stats
    users.js         → GET/POST /api/admin/users
    [id]/toggle.js   → PUT /api/admin/users/[id]/toggle
    [id].js          → DELETE /api/admin/users/[id]
    deposit.js       → POST /api/admin/deposit
    transactions.js  → GET /api/admin/transactions
    settings.js      → PUT /api/admin/settings
  /weather
    index.js         → GET /api/weather
```

---

## Password Security (bcrypt)

```js
// NEVER store plain passwords. In register.js:
const bcrypt = require('bcryptjs');

const SALT_ROUNDS = 12; // cost factor — high enough to slow brute force

async function hashPassword(plainText) {
  return bcrypt.hash(plainText, SALT_ROUNDS);
  // result: "$2b$12$..." — the salt is embedded in the hash
}

async function verifyPassword(plainText, hash) {
  return bcrypt.compare(plainText, hash);
  // timing-safe comparison built in
}
```

---

## MongoDB User Schema (Mongoose)

```js
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, trim: true },
  location: { type: String, trim: true },
  passwordHash: { type: String, required: true }, // bcrypt(12) hash ONLY
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  isActive: { type: Boolean, default: true },
  walletBalance: { type: Number, default: 0, min: 0 },
  failedLoginAttempts: { type: Number, default: 0 },
  lockedUntil: { type: Date },
  refreshTokens: [{ token: String, expiresAt: Date, ip: String }], // hashed
  createdAt: { type: Date, default: Date.now },
});

// NEVER select passwordHash in queries by default
userSchema.set('toJSON', {
  transform: (doc, ret) => { delete ret.passwordHash; delete ret.refreshTokens; return ret; }
});
```

---

## JWT Auth Flow

```js
const jwt = require('jsonwebtoken');

// Access token — short-lived, sent in response body, stored in memory only (NOT localStorage)
function signAccessToken(userId, role) {
  return jwt.sign({ sub: userId, role }, process.env.JWT_PRIVATE_KEY, {
    algorithm: 'RS256',
    expiresIn: '15m',
  });
}

// Refresh token — long-lived, stored as httpOnly Secure SameSite=Strict cookie
function signRefreshToken(userId) {
  return jwt.sign({ sub: userId }, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '7d' });
}

// Set refresh cookie (server-side)
res.cookie('refreshToken', refreshToken, {
  httpOnly: true,
  secure: true,
  sameSite: 'strict',
  maxAge: 7 * 24 * 60 * 60 * 1000,
  path: '/api/auth',
});
```

---

## Rate Limiting

```js
const rateLimit = require('express-rate-limit');

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                   // 5 attempts per IP per window
  message: { message: 'Too many login attempts. Please try again in 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false,
});
```

---

## Security Middleware (apply to all routes)

```js
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');

app.use(helmet());               // Sets 15+ security HTTP headers
app.use(mongoSanitize());        // Strips $ and . from req.body (prevents NoSQL injection)
app.use(xss());                  // Sanitizes user input (XSS prevention)
app.use(express.json({ limit: '10kb' })); // Prevent large payload attacks
```

---

## Admin Route Guard

```js
function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied: Admins only' });
  }
  next();
}
// Log every admin action for audit trail
```

---

## MongoDB Atlas Security Checklist

- ✅ IP Whitelist: Only allow Vercel's outbound IPs
- ✅ Atlas user has minimum permissions (readWrite on agronexus DB only)
- ✅ Encryption at rest: AES-256 (default in Atlas M10+)
- ✅ TLS 1.3 in transit
- ✅ MONGODB_URI stored in Vercel env vars ONLY
- ✅ Never commit .env to git — add to .gitignore
