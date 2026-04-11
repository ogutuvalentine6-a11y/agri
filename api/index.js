const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();

// Midleware
app.use(helmet());
app.use(cors({
  origin: ['https://agri-gamma-red.vercel.app', 'http://localhost:3000', 'http://127.0.0.1:5500'],
  credentials: true
}));
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());

// Serve static HTML files from parent directory
const staticPath = path.join(__dirname, '..');
app.use(express.static(staticPath));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: 'Too many requests, please try again later.' }
});
app.use('/api/', limiter);

// MongoDB Connection
let isConnected = false;

async function connectToDatabase() {
  // On serverless, readyState 1 = connected; reuse it even if flag was reset
  if (isConnected && mongoose.connection.readyState === 1) return;
  
  if (!process.env.MONGODB_URI) {
    throw new Error('MONGODB_URI is not defined');
  }
  
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
    });
    isConnected = true;
    console.log('MongoDB connected');
  } catch (error) {
    isConnected = false; // reset so next request retries
    console.error('MongoDB connection error:', error);
    throw error;
  }
}

// ==================== MODELS ====================

// User Schema
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  phone: { type: String, trim: true },
  location: { type: String, trim: true },
  passwordHash: { type: String, required: true, select: false },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  isActive: { type: Boolean, default: true },
  walletBalance: { type: Number, default: 0, min: 0 },
  failedLoginAttempts: { type: Number, default: 0 },
  lockedUntil: { type: Date, default: null },
  refreshTokens: [{ token: String, expiresAt: Date, ip: String }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
}, {
  toJSON: { transform: (doc, ret) => {
    delete ret.passwordHash;
    delete ret.refreshTokens;
    delete ret.__v;
    return ret;
  }}
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('passwordHash')) return next();
  const rounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
  this.passwordHash = await bcrypt.hash(this.passwordHash, rounds);
  next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.passwordHash);
};

userSchema.methods.isLocked = function() {
  return this.lockedUntil && this.lockedUntil > new Date();
};

userSchema.methods.incrementFailedAttempts = async function() {
  this.failedLoginAttempts += 1;
  if (this.failedLoginAttempts >= 5) {
    this.lockedUntil = new Date(Date.now() + 15 * 60 * 1000);
  }
  await this.save();
};

userSchema.methods.resetFailedAttempts = async function() {
  this.failedLoginAttempts = 0;
  this.lockedUntil = null;
  await this.save();
};

// Transaction Schema
const transactionSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  type: { type: String, enum: ['deposit', 'withdrawal', 'purchase', 'refund', 'manual_deposit'], required: true },
  amount: { type: Number, required: true, min: 0 },
  status: { type: String, enum: ['pending', 'completed', 'failed', 'cancelled'], default: 'pending' },
  method: { type: String, enum: ['mpesa', 'bank', 'card', 'airtel', 'manual', 'wallet'], default: 'manual' },
  reference: { type: String, unique: true, sparse: true },
  description: { type: String, trim: true },
  adminNote: { type: String, trim: true },
  adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  balanceAfter: { type: Number, default: 0 },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  completedAt: { type: Date },
  createdAt: { type: Date, default: Date.now }
});

transactionSchema.pre('save', async function(next) {
  if (!this.reference) {
    const prefix = this.type === 'deposit' ? 'DEP' : this.type === 'withdrawal' ? 'WD' : 'TXN';
    const timestamp = Date.now().toString(36).toUpperCase();
    const random = Math.random().toString(36).substring(2, 6).toUpperCase();
    this.reference = `${prefix}-${timestamp}-${random}`;
  }
  next();
});

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Transaction = mongoose.models.Transaction || mongoose.model('Transaction', transactionSchema);

// ==================== AUTH HELPER FUNCTIONS ====================

function generateAccessToken(userId, role) {
  return jwt.sign(
    { sub: userId, role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
  );
}

function generateRefreshToken(userId) {
  return jwt.sign(
    { sub: userId },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
  );
}

function verifyAccessToken(token) {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    return null;
  }
}

function verifyRefreshToken(token) {
  try {
    return jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
  } catch (error) {
    return null;
  }
}

// ==================== MIDDLEWARE ====================

async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided' });
  }
  
  const token = authHeader.substring(7);
  const decoded = verifyAccessToken(token);
  
  if (!decoded) {
    return res.status(401).json({ message: 'Invalid or expired token' });
  }
  
  req.user = { id: decoded.sub, role: decoded.role };
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ message: 'Access denied. Admin privileges required.' });
  }
  next();
}

// ==================== ROUTES ====================

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ========== AUTH ROUTES ==========

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }
  
  try {
    await connectToDatabase();
    
    const user = await User.findOne({ email }).select('+passwordHash');
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    if (user.isLocked()) {
      const waitMinutes = Math.ceil((user.lockedUntil - new Date()) / 60000);
      return res.status(401).json({ message: `Account locked. Try again in ${waitMinutes} minutes.` });
    }
    
    if (!user.isActive) {
      return res.status(401).json({ message: 'Account has been suspended. Contact support.' });
    }
    
    const isValid = await user.comparePassword(password);
    if (!isValid) {
      await user.incrementFailedAttempts();
      return res.status(401).json({ message: 'Invalid email or password' });
    }
    
    await user.resetFailedAttempts();
    
    const accessToken = generateAccessToken(user._id, user.role);
    const refreshToken = generateRefreshToken(user._id);
    
    user.refreshTokens.push({
      token: refreshToken,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      ip: req.headers['x-forwarded-for'] || req.socket.remoteAddress
    });
    await user.save();
    
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: '/api/auth'
    });
    
    res.json({
      accessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        walletBalance: user.walletBalance
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Register
app.post('/api/auth/register', async (req, res) => {
  const { name, email, phone, location, password } = req.body;
  
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email and password are required' });
  }
  
  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters' });
  }
  
  const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ message: 'Please provide a valid email address' });
  }
  
  try {
    await connectToDatabase();
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'User with this email already exists' });
    }
    
    const user = new User({
      name,
      email,
      phone: phone || '',
      location: location || '',
      passwordHash: password,
      role: 'user',
      walletBalance: 0
    });
    
    await user.save();
    
    res.status(201).json({
      message: 'User registered successfully',
      user: { id: user._id, name: user.name, email: user.email, role: user.role }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Refresh token
app.post('/api/auth/refresh', async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  
  if (!refreshToken) {
    return res.status(401).json({ message: 'No refresh token provided' });
  }
  
  try {
    const decoded = verifyRefreshToken(refreshToken);
    if (!decoded) {
      return res.status(401).json({ message: 'Invalid or expired refresh token' });
    }
    
    await connectToDatabase();
    
    const user = await User.findById(decoded.sub);
    if (!user || !user.isActive) {
      return res.status(401).json({ message: 'User not found or inactive' });
    }
    
    const tokenExists = user.refreshTokens.some(t => t.token === refreshToken);
    if (!tokenExists) {
      return res.status(401).json({ message: 'Refresh token not recognized' });
    }
    
    const newAccessToken = generateAccessToken(user._id, user.role);
    
    res.json({
      accessToken: newAccessToken,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        walletBalance: user.walletBalance
      }
    });
  } catch (error) {
    console.error('Refresh error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Logout
app.post('/api/auth/logout', async (req, res) => {
  const refreshToken = req.cookies?.refreshToken;
  
  if (refreshToken) {
    try {
      await connectToDatabase();
      await User.updateOne(
        { 'refreshTokens.token': refreshToken },
        { $pull: { refreshTokens: { token: refreshToken } } }
      );
    } catch (error) {
      console.error('Logout error:', error);
    }
  }
  
  res.clearCookie('refreshToken', { path: '/api/auth' });
  res.json({ message: 'Logged out successfully' });
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }
  
  try {
    await connectToDatabase();
    const user = await User.findOne({ email });
    
    if (user) {
      console.log(`Password reset requested for: ${email}`);
    }
    
    res.json({ message: 'If account exists, password reset link has been sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ========== USER ROUTES ==========

// Get current user
app.get('/api/users/me', authenticate, async (req, res) => {
  try {
    await connectToDatabase();
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    res.json({
      id: user._id,
      name: user.name,
      email: user.email,
      phone: user.phone,
      location: user.location,
      role: user.role,
      walletBalance: user.walletBalance,
      isActive: user.isActive,
      createdAt: user.createdAt
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get user stats
app.get('/api/users/stats', authenticate, async (req, res) => {
  try {
    await connectToDatabase();
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const deposits = await Transaction.aggregate([
      { $match: { userId: user._id, type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const withdrawals = await Transaction.aggregate([
      { $match: { userId: user._id, type: 'withdrawal', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const recentTransactions = await Transaction.find({ userId: user._id })
      .sort({ createdAt: -1 })
      .limit(10);
    
    res.json({
      balance: user.walletBalance,
      totalDeposits: deposits[0]?.total || 0,
      totalWithdrawals: withdrawals[0]?.total || 0,
      totalPurchases: 0,
      trades: 0,
      recentTransactions
    });
  } catch (error) {
    console.error('User stats error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update profile
app.put('/api/users/profile', authenticate, async (req, res) => {
  const { name, email, phone, location, currentPassword } = req.body;
  
  if (!name || !email || !currentPassword) {
    return res.status(400).json({ message: 'Name, email and current password are required' });
  }
  
  try {
    await connectToDatabase();
    
    const user = await User.findById(req.user.id).select('+passwordHash');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const isValid = await user.comparePassword(currentPassword);
    if (!isValid) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }
    
    user.name = name;
    user.email = email;
    user.phone = phone || user.phone;
    user.location = location || user.location;
    user.updatedAt = new Date();
    await user.save();
    
    res.json({ message: 'Profile updated successfully', user });
  } catch (error) {
    console.error('Update profile error:', error);
    if (error.code === 11000) {
      return res.status(409).json({ message: 'Email already in use' });
    }
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Change password
app.put('/api/users/change-password', authenticate, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Current and new password are required' });
  }
  
  if (newPassword.length < 8) {
    return res.status(400).json({ message: 'New password must be at least 8 characters' });
  }
  
  try {
    await connectToDatabase();
    
    const user = await User.findById(req.user.id).select('+passwordHash');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const isValid = await user.comparePassword(currentPassword);
    if (!isValid) {
      return res.status(401).json({ message: 'Current password is incorrect' });
    }
    
    user.passwordHash = newPassword;
    user.refreshTokens = [];
    await user.save();
    
    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ========== TRANSACTION ROUTES ==========

// Get transactions
app.get('/api/transactions', authenticate, async (req, res) => {
  const { type, limit = 50, page = 1 } = req.query;
  
  try {
    await connectToDatabase();
    
    const query = { userId: req.user.id };
    if (type && type !== 'all') query.type = type;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limit));
    
    const total = await Transaction.countDocuments(query);
    
    res.json({
      transactions,
      pagination: { page: parseInt(page), limit: parseInt(limit), total, pages: Math.ceil(total / parseInt(limit)) }
    });
  } catch (error) {
    console.error('Get transactions error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Deposit
app.post('/api/transactions/deposit', authenticate, async (req, res) => {
  const { amount, method, reference } = req.body;
  
  if (!amount || amount < 50) {
    return res.status(400).json({ message: 'Minimum deposit amount is KES 50' });
  }
  
  if (amount > 1000000) {
    return res.status(400).json({ message: 'Maximum deposit amount is KES 1,000,000' });
  }
  
  try {
    await connectToDatabase();
    
    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const transaction = new Transaction({
      userId: user._id,
      type: 'deposit',
      amount,
      status: 'completed',
      method: method || 'manual',
      description: reference || `Deposit via ${method || 'manual'}`,
      completedAt: new Date(),
      balanceAfter: user.walletBalance + amount
    });
    
    await transaction.save();
    
    user.walletBalance += amount;
    await user.save();
    
    res.status(201).json({
      message: 'Deposit successful',
      transaction: { id: transaction._id, reference: transaction.reference, amount, status: 'completed' }
    });
  } catch (error) {
    console.error('Deposit error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Withdraw
app.post('/api/transactions/withdraw', authenticate, async (req, res) => {
  const { amount, destination, accountNumber, password } = req.body;
  
  if (!amount || amount < 100) {
    return res.status(400).json({ message: 'Minimum withdrawal amount is KES 100' });
  }
  
  if (!destination || !accountNumber) {
    return res.status(400).json({ message: 'Destination and account number are required' });
  }
  
  if (!password) {
    return res.status(400).json({ message: 'Password is required for withdrawal' });
  }
  
  try {
    await connectToDatabase();
    
    const user = await User.findById(req.user.id).select('+passwordHash');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const isValid = await user.comparePassword(password);
    if (!isValid) {
      return res.status(401).json({ message: 'Password is incorrect' });
    }
    
    const fee = amount * 0.015;
    const totalDeduction = amount + fee;
    
    if (user.walletBalance < totalDeduction) {
      return res.status(400).json({ message: `Insufficient balance including ${fee} KES withdrawal fee` });
    }
    
    const transaction = new Transaction({
      userId: user._id,
      type: 'withdrawal',
      amount,
      status: 'pending',
      method: destination,
      description: `Withdrawal to ${destination}`,
      metadata: { accountNumber, fee }
    });
    
    await transaction.save();
    
    res.status(201).json({
      message: 'Withdrawal request submitted. Pending admin approval.',
      transaction: { id: transaction._id, reference: transaction.reference, amount, fee, status: 'pending' }
    });
  } catch (error) {
    console.error('Withdrawal error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// ========== ADMIN ROUTES ==========

// Admin stats
app.get('/api/admin/stats', authenticate, requireAdmin, async (req, res) => {
  try {
    await connectToDatabase();
    
    const totalUsers = await User.countDocuments();
    const totalBalance = await User.aggregate([{ $group: { _id: null, total: { $sum: '$walletBalance' } } }]);
    const totalDeposits = await Transaction.aggregate([
      { $match: { type: 'deposit', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    const totalWithdrawals = await Transaction.aggregate([
      { $match: { type: 'withdrawal', status: 'completed' } },
      { $group: { _id: null, total: { $sum: '$amount' } } }
    ]);
    
    const lastMonth = new Date();
    lastMonth.setMonth(lastMonth.getMonth() - 1);
    const newUsersThisMonth = await User.countDocuments({ createdAt: { $gte: lastMonth } });
    
    const recentActivity = await Transaction.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('userId', 'name email');
    
    res.json({
      totalUsers,
      totalBalance: totalBalance[0]?.total || 0,
      totalDeposits: totalDeposits[0]?.total || 0,
      totalWithdrawals: totalWithdrawals[0]?.total || 0,
      totalTrades: 0,
      newUsersThisMonth,
      monthlyRevenue: [12000, 18000, 24000, 32000, 28000, 41000, 38000, 52000, 47000, 61000, 58000, 72000],
      monthLabels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'],
      recentActivity: recentActivity.map(t => ({
        userName: t.userId?.name || 'Unknown',
        type: t.type,
        amount: t.amount,
        createdAt: t.createdAt,
        status: t.status
      })),
      systemAlerts: [
        { level: 'info', msg: 'All systems operational' },
        { level: 'warning', msg: '3 pending withdrawal requests awaiting review' }
      ]
    });
  } catch (error) {
    console.error('Admin stats error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get users (admin)
app.get('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
  const { search, role, status, page = 1, limit = 20 } = req.query;
  
  try {
    await connectToDatabase();
    
    const query = {};
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { phone: { $regex: search, $options: 'i' } }
      ];
    }
    if (role) query.role = role;
    if (status === 'active') query.isActive = true;
    if (status === 'suspended') query.isActive = false;
    
    const skip = (parseInt(page) - 1) * parseInt(limit);
    const users = await User.find(query).sort({ createdAt: -1 }).skip(skip).limit(parseInt(limit));
    const total = await User.countDocuments(query);
    
    res.json({ users, total, page: parseInt(page), pages: Math.ceil(total / parseInt(limit)) });
  } catch (error) {
    console.error('Admin get users error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Create user (admin)
app.post('/api/admin/users', authenticate, requireAdmin, async (req, res) => {
  const { name, email, phone, location, role, password } = req.body;
  
  if (!name || !email || !password) {
    return res.status(400).json({ message: 'Name, email and password are required' });
  }
  
  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters' });
  }
  
  try {
    await connectToDatabase();
    
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'User with this email already exists' });
    }
    
    const user = new User({
      name,
      email,
      phone: phone || '',
      location: location || '',
      role: role || 'user',
      passwordHash: password
    });
    
    await user.save();
    res.status(201).json({ message: 'User created successfully', user });
  } catch (error) {
    console.error('Admin create user error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Delete user (admin)
app.delete('/api/admin/users/:id', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  if (id === req.user.id) {
    return res.status(400).json({ message: 'Cannot delete your own account' });
  }
  
  try {
    await connectToDatabase();
    
    const user = await User.findByIdAndDelete(id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    await Transaction.deleteMany({ userId: id });
    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Admin delete user error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Toggle user status (admin)
app.put('/api/admin/users/:id/toggle', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  if (id === req.user.id) {
    return res.status(400).json({ message: 'Cannot modify your own status' });
  }
  
  try {
    await connectToDatabase();
    
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    user.isActive = !user.isActive;
    await user.save();
    
    res.json({ message: `User ${user.isActive ? 'activated' : 'suspended'} successfully`, isActive: user.isActive });
  } catch (error) {
    console.error('Admin toggle user error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Admin manual deposit
app.post('/api/admin/deposit', authenticate, requireAdmin, async (req, res) => {
  const { userId, amount, method, adminNote } = req.body;
  
  if (!userId || !amount || amount < 1) {
    return res.status(400).json({ message: 'User ID and valid amount are required' });
  }
  
  if (!adminNote) {
    return res.status(400).json({ message: 'Admin note is required for audit trail' });
  }
  
  try {
    await connectToDatabase();
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    
    const transaction = new Transaction({
      userId: user._id,
      type: 'manual_deposit',
      amount,
      status: 'completed',
      method: method || 'manual',
      description: 'Manual deposit by admin',
      adminNote,
      adminId: req.user.id,
      completedAt: new Date(),
      balanceAfter: user.walletBalance + amount
    });
    
    await transaction.save();
    
    user.walletBalance += amount;
    await user.save();
    
    res.json({
      message: `Successfully deposited KES ${amount.toLocaleString()} to ${user.name}`,
      transaction: { id: transaction._id, reference: transaction.reference, amount, newBalance: user.walletBalance }
    });
  } catch (error) {
    console.error('Admin deposit error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get all transactions (admin)
app.get('/api/admin/transactions', authenticate, requireAdmin, async (req, res) => {
  const { search, type, status, limit = 50 } = req.query;
  
  try {
    await connectToDatabase();
    
    const query = {};
    // admin.html loadManualDeps sends type=manual — map it to the actual enum value
    if (type === 'manual') query.type = 'manual_deposit';
    else if (type) query.type = type;
    if (status) query.status = status;
    
    if (search) {
      const users = await User.find({
        $or: [
          { name: { $regex: search, $options: 'i' } },
          { email: { $regex: search, $options: 'i' } }
        ]
      }).select('_id');
      query.userId = { $in: users.map(u => u._id) };
    }
    
    const transactions = await Transaction.find(query)
      .sort({ createdAt: -1 })
      .limit(parseInt(limit))
      .populate('userId', 'name email');
    
    res.json({ transactions: transactions.map(t => ({
      ...t.toObject(),
      userName: t.userId?.name || 'Unknown',
      userEmail: t.userId?.email || ''
    })) });
  } catch (error) {
    console.error('Admin get transactions error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update settings (admin)
app.put('/api/admin/settings', authenticate, requireAdmin, async (req, res) => {
  const { platformName, minDeposit, minWithdrawal, withdrawalFee, maintenanceMode } = req.body;
  
  try {
    console.log('Settings updated:', { platformName, minDeposit, minWithdrawal, withdrawalFee, maintenanceMode });
    res.json({ message: 'Settings saved successfully' });
  } catch (error) {
    console.error('Save settings error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Approve pending transaction (admin)
app.put('/api/admin/transactions/:id/approve', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    await connectToDatabase();
    
    const transaction = await Transaction.findById(id);
    if (!transaction) {
      return res.status(404).json({ message: 'Transaction not found' });
    }
    
    if (transaction.status !== 'pending') {
      return res.status(400).json({ message: 'Transaction is not pending' });
    }
    
    // For withdrawals, deduct balance on approval
    if (transaction.type === 'withdrawal') {
      const user = await User.findById(transaction.userId);
      if (!user) return res.status(404).json({ message: 'User not found' });
      
      const fee = transaction.metadata?.fee || 0;
      const totalDeduction = transaction.amount + fee;
      
      if (user.walletBalance < totalDeduction) {
        transaction.status = 'failed';
        await transaction.save();
        return res.status(400).json({ message: 'Insufficient user balance — transaction failed' });
      }
      
      user.walletBalance -= totalDeduction;
      transaction.balanceAfter = user.walletBalance;
      await user.save();
    }
    
    transaction.status = 'completed';
    transaction.completedAt = new Date();
    transaction.adminId = req.user.id;
    await transaction.save();
    
    res.json({ message: 'Transaction approved successfully', transaction });
  } catch (error) {
    console.error('Approve transaction error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Reject pending transaction (admin)
app.put('/api/admin/transactions/:id/reject', authenticate, requireAdmin, async (req, res) => {
  const { id } = req.params;
  
  try {
    await connectToDatabase();
    
    const transaction = await Transaction.findById(id);
    if (!transaction) {
      return res.status(404).json({ message: 'Transaction not found' });
    }
    
    if (transaction.status !== 'pending') {
      return res.status(400).json({ message: 'Transaction is not pending' });
    }
    
    transaction.status = 'cancelled';
    transaction.adminId = req.user.id;
    await transaction.save();
    
    res.json({ message: 'Transaction rejected successfully', transaction });
  } catch (error) {
    console.error('Reject transaction error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update security settings (admin)
app.put('/api/admin/settings/security', authenticate, requireAdmin, async (req, res) => {
  const { maxLoginAttempts, sessionDuration, jwtExpiry, require2FA } = req.body;
  
  try {
    console.log('Security settings updated:', { maxLoginAttempts, sessionDuration, jwtExpiry, require2FA });
    res.json({ message: 'Security settings saved successfully' });
  } catch (error) {
    console.error('Save security settings error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});



// Get weather
app.get('/api/weather', async (req, res) => {
  const { location = 'Nakuru,KE' } = req.query;
  
  try {
    let weatherData;
    
    if (process.env.OPENWEATHER_API_KEY && process.env.OPENWEATHER_API_KEY !== 'your-openweathermap-api-key') {
      const response = await fetch(
        `https://api.openweathermap.org/data/2.5/weather?q=${location}&units=metric&appid=${process.env.OPENWEATHER_API_KEY}`
      );
      const data = await response.json();
      
      weatherData = {
        temp: Math.round(data.main?.temp || 24),
        description: data.weather?.[0]?.description || 'Partly Cloudy',
        humidity: data.main?.humidity || 72,
        wind: Math.round(data.wind?.speed || 12),
        feelsLike: Math.round(data.main?.feels_like || 22),
        icon: data.weather?.[0]?.icon || '01d'
      };
    } else {
      weatherData = {
        temp: 24,
        description: 'Partly Cloudy',
        humidity: 72,
        wind: 12,
        feelsLike: 22,
        icon: '02d'
      };
    }
    
    const forecast = [
      { day: 'Mon', high: 27, low: 18, icon: '☀️' },
      { day: 'Tue', high: 20, low: 15, icon: '🌧️' },
      { day: 'Wed', high: 23, low: 17, icon: '⛅' },
      { day: 'Thu', high: 25, low: 18, icon: '🌤️' },
      { day: 'Fri', high: 22, low: 16, icon: '🌦️' },
      { day: 'Sat', high: 24, low: 17, icon: '🌤️' },
      { day: 'Sun', high: 26, low: 19, icon: '☀️' }
    ];
    
    const alerts = [
      { level: 'warning', message: 'Heavy rainfall expected Tuesday. Harvest ripe crops by Monday.' }
    ];
    
    res.json({ ...weatherData, forecast, alerts });
  } catch (error) {
    console.error('Weather error:', error);
    res.json({
      temp: 24,
      description: 'Partly Cloudy',
      humidity: 72,
      wind: 12,
      feelsLike: 22,
      icon: '02d',
      forecast: [],
      alerts: []
    });
  }
});

// Serve HTML files
app.get('/', (req, res) => {
  res.sendFile(path.join(staticPath, 'index.html'));
});

app.get('/user.html', (req, res) => {
  res.sendFile(path.join(staticPath, 'user.html'));
});

app.get('/admin.html', (req, res) => {
  res.sendFile(path.join(staticPath, 'admin.html'));
});

// 404 handler
app.use('*', (req, res) => {
  if (req.path.startsWith('/api')) {
    res.status(404).json({ message: 'API route not found' });
  } else {
    res.sendFile(path.join(staticPath, 'index.html'));
  }
});

module.exports = app;
