import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import dotenv from 'dotenv';
import Razorpay from 'razorpay';
import fetch from 'node-fetch';
import https from 'https';
import crypto from 'crypto';
import { sendEmail, smtpIsConfigured } from './utils/emailService.js';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors({
  origin: 'http://localhost:5173', // Allow requests from frontend
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

// Configure HTTPS agent for insecure requests
const agent = new https.Agent({
  rejectUnauthorized: false // Ignore SSL certificate issues
});

// Initialize Razorpay instance (only if credentials are available)
let razorpay = null;
if (process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET) {
  razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID,
    key_secret: process.env.RAZORPAY_KEY_SECRET,
  });
} else {
  console.warn('Razorpay credentials not found. Payment features will be disabled.');
}

// Log all requests
app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
  next();
});

// MongoDB Atlas Connection
const connectDB = async () => {
  try {
    if (!process.env.MONGODB_URI) {
      console.warn('MongoDB URI not found. Database features will be disabled.');
      return;
    }

    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB Atlas connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    console.warn('Database connection failed. Server will start without database connectivity.');
  }
};

// User Schema
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    trim: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  system_specs: {
    os_version: {
      type: String,
      required: true
    },
    processor: {
      intel: {
        type: String,
        default: ''
      },
      amd: {
        type: String,
        default: ''
      }
    },
    RAM: {
      type: String,
      required: true
    },
    graphics_card: {
      type: String,
      required: true
    },
    disk: {
      type: String,
      required: true
    }
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  }
  ,
  // Keep track of ratings given by this user across games
  ratings: [{ gameId: { type: mongoose.Schema.Types.ObjectId, ref: 'Game' }, value: Number, updatedAt: { type: Date, default: Date.now } }]
  ,
  // Password reset token and expiry
  resetPasswordToken: { type: String },
  resetPasswordExpires: { type: Date }
});

// Create User model
const User = mongoose.model('User', userSchema);

// Game Schema
const gameSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  image: { type: String },
  price: { type: Number, required: true },
  genre: { type: String },
  detailsJsonUrl: { type: String }, // Store the JSON link
  // Ratings: store per-user ratings and aggregates (average/count/total)
  ratings: {
    total: { type: Number, default: 0 }, // sum of all rating values
    count: { type: Number, default: 0 }, // number of ratings
    average: { type: Number, default: 0 },
    // Optional: keep per-user ratings to prevent duplicate votes and allow updates
    userRatings: [{ userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }, value: Number }]
  },
  createdAt: { type: Date, default: Date.now }
});

const Game = mongoose.model('Game', gameSchema);



// Cart Schema
const cartSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  items: [{
    gameId: { type: mongoose.Schema.Types.ObjectId, ref: 'Game', required: true },
    title: { type: String, required: true },
    price: { type: Number, required: true },
    image: { type: String },
    logo: { type: String },
    quantity: { type: Number, default: 1, min: 1 }
  }],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Cart = mongoose.model('Cart', cartSchema);

// Order Schema
const orderSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  gameId: { type: mongoose.Schema.Types.ObjectId, ref: 'Game', required: true },
  title: { type: String, required: true },
  price: { type: Number, required: true },
  quantity: { type: Number, default: 1 },
  paymentMethod: { type: String, required: true },
  status: { type: String, enum: ['pending', 'completed', 'failed'], default: 'pending' },
  orderId: { type: String, unique: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const Order = mongoose.model('Order', orderSchema);

// Library Schema
const librarySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  games: [{
    gameId: { type: mongoose.Schema.Types.ObjectId, ref: 'Game', required: true },
    title: { type: String, required: true },
    downloadUrl: { type: String, required: true },
    addedAt: { type: Date, default: Date.now }
  }]
});

const Library = mongoose.model('Library', librarySchema);

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Rating endpoints for games
// Submit or update a rating (1-5) for a game
app.post('/api/games/:id/rate', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { rating } = req.body;
    const userId = req.user && req.user.userId;

    // Basic validation
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'Invalid game ID' });
    }

    const ratingNum = Number(rating);
    if (!rating || Number.isNaN(ratingNum) || ratingNum < 1 || ratingNum > 5) {
      return res.status(400).json({ message: 'Rating must be a number between 1 and 5' });
    }

    const game = await Game.findById(id);
    if (!game) return res.status(404).json({ message: 'Game not found' });

    // Ensure ratings structure exists to avoid runtime errors
    game.ratings = game.ratings || {};
    game.ratings.userRatings = Array.isArray(game.ratings.userRatings) ? game.ratings.userRatings : [];
    game.ratings.total = typeof game.ratings.total === 'number' ? game.ratings.total : 0;
    game.ratings.count = typeof game.ratings.count === 'number' ? game.ratings.count : 0;

    // Check if user has already rated
    const existing = game.ratings.userRatings.find(r => r.userId && r.userId.toString() === String(userId));

    if (existing) {
      // Update totals by removing old value and adding new
      game.ratings.total = game.ratings.total - existing.value + ratingNum;
      existing.value = ratingNum;
    } else {
      // New rating
  game.ratings.userRatings.push({ userId: new mongoose.Types.ObjectId(userId), value: ratingNum });
      game.ratings.total = game.ratings.total + ratingNum;
      game.ratings.count = game.ratings.count + 1;
    }

    // Recalculate average
    game.ratings.average = game.ratings.count > 0 ? (game.ratings.total / game.ratings.count) : 0;

    await game.save();

    // Also persist the user's rating on their profile for quick lookup
    try {
      if (userId) {
        const user = await User.findById(userId);
        if (user) {
          user.ratings = Array.isArray(user.ratings) ? user.ratings : [];
          const existingUserRating = user.ratings.find(r => r.gameId && r.gameId.toString() === id);
          if (existingUserRating) {
            existingUserRating.value = ratingNum;
            existingUserRating.updatedAt = new Date();
          } else {
            user.ratings.push({ gameId: new mongoose.Types.ObjectId(id), value: ratingNum, updatedAt: new Date() });
          }
          await user.save();
        }
      }
    } catch (userRatingErr) {
      console.warn('Failed to persist user rating to user profile:', userRatingErr);
    }

    res.json({
      message: 'Rating saved',
      rating: {
        average: game.ratings.average,
        count: game.ratings.count,
        total: game.ratings.total,
        percentage: Math.round(((game.ratings.average || 0) / 5) * 100)
      }
    });
  } catch (error) {
    console.error('Rate game error:', error && error.stack ? error.stack : error);
    res.status(500).json({ message: 'Error saving rating', error: error && error.message ? error.message : String(error) });
  }
});

// Get rating summary for a game (optional user-specific rating if authenticated)
app.get('/api/games/:id/rating', async (req, res) => {
  try {
    const { id } = req.params;
    let userId = null;
    // Try to extract token from header to identify user's rating (non-blocking)
    const authHeader = req.headers['authorization'];
    if (authHeader) {
      const token = authHeader.split(' ')[1];
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        userId = decoded.userId;
      } catch (e) {
        // ignore invalid token
      }
    }

    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'Invalid game ID' });
    }

    const game = await Game.findById(id).lean();
    if (!game) return res.status(404).json({ message: 'Game not found' });

    const summary = {
      average: game.ratings?.average || 0,
      count: game.ratings?.count || 0,
      total: game.ratings?.total || 0,
      userRating: null,
      userRatingsCount: null
    };

    if (userId && game.ratings && Array.isArray(game.ratings.userRatings)) {
      const ur = game.ratings.userRatings.find(r => r.userId && r.userId.toString() === userId);
      if (ur) summary.userRating = ur.value;
      try {
        const user = await User.findById(userId).lean();
        if (user && Array.isArray(user.ratings)) {
          summary.userRatingsCount = user.ratings.length;
        }
      } catch (e) {
        // ignore user lookup errors
      }
    }

  // include percentage (0-100) based on average out of 5
  summary.percentage = Math.round(((summary.average || 0) / 5) * 100);

  res.json(summary);
  } catch (error) {
    console.error('Get game rating error:', error);
    res.status(500).json({ message: 'Error fetching rating' });
  }
});

// Razorpay payment verification endpoint
app.post('/api/razorpay/verify', authenticateToken, async (req, res) => {
  try {
    console.log('Payment verification request received:', req.body); // Debug log
    const { 
      razorpay_payment_id, 
      razorpay_order_id, 
      razorpay_signature,
      gameId  // Add gameId to know which game to add to library
    } = req.body;
    
    if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature || !gameId) {
      console.error('Missing parameters:', { 
        razorpay_payment_id, 
        razorpay_order_id, 
        razorpay_signature,
        gameId 
      });
      return res.status(400).json({ 
        success: false, 
        message: 'Missing payment verification parameters' 
      });
    }

    // Step 1: Verify signature (if Razorpay secret is available)
    if (process.env.RAZORPAY_KEY_SECRET) {
      // crypto is imported at the top of the file
      console.log('Generating signature with order_id and payment_id:', 
        { razorpay_order_id, razorpay_payment_id }); // Debug log
      
      const generated_signature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(razorpay_order_id + '|' + razorpay_payment_id)
        .digest('hex');

      console.log('Signature comparison:', { 
        generated: generated_signature,
        received: razorpay_signature,
        matches: generated_signature === razorpay_signature
      }); // Debug log

      if (generated_signature !== razorpay_signature) {
        console.error('Signature verification failed');
        return res.status(400).json({
          success: false,
          message: 'Invalid payment signature'
        });
      }
      console.log('Signature verification successful'); // Debug log
    } else {
      console.warn('Razorpay secret not configured - skipping signature verification in test mode');
    }

    // Step 2: Verify payment status from Razorpay (if available)
    if (razorpay) {
      try {
        const payment = await razorpay.payments.fetch(razorpay_payment_id);

        if (payment.status !== 'captured') {
          return res.status(400).json({
            success: false,
            message: 'Payment not captured'
          });
        }
      } catch (apiError) {
        console.error('Razorpay API error:', apiError);
        return res.status(500).json({
          success: false,
          message: 'Payment verification service unavailable'
        });
      }
    } else {
      console.warn('Razorpay not configured - skipping payment status verification');
    }

    // Step 3: Add game to user's library (if database is available)
    if (mongoose.connection.readyState === 1) {
      try {
        console.log('Looking for game with ID:', gameId); // Debug log
        const game = await Game.findById(gameId);
        if (!game) {
          console.error('Game not found with ID:', gameId);
          return res.status(404).json({
            success: false,
            message: 'Game not found'
          });
        }
        console.log('Game found:', game.title); // Debug log

        // Find or create user's library
        console.log('Looking for library for user:', req.user.userId); // Debug log
        let library = await Library.findOne({ userId: req.user.userId });
        if (!library) {
          console.log('Creating new library for user'); // Debug log
          library = new Library({
            userId: req.user.userId,
            games: []
          });
        }
        console.log('Current library state:', library); // Debug log

        // Check if game already exists in library
        console.log('Checking if game exists in library'); // Debug log
        const gameExists = library.games.some(g => g.gameId.toString() === gameId);
        if (!gameExists) {
          console.log('Adding game to library'); // Debug log
          library.games.push({
            gameId: game._id,
            title: game.title,
            image: game.image, // Add image field
            downloadUrl: `/api/games/download/${game._id}`,
            addedAt: new Date()
          });
          const savedLibrary = await library.save();
          console.log('Library saved successfully:', savedLibrary); // Debug log
        } else {
          console.log('Game already exists in library'); // Debug log
        }

        // Update order status
        console.log('Updating order status:', razorpay_order_id); // Debug log
        const updatedOrder = await Order.findOneAndUpdate(
          { orderId: razorpay_order_id },
          {
            status: 'completed',
            paymentId: razorpay_payment_id
          },
          { new: true }
        );
        console.log('Order updated:', updatedOrder); // Debug log
      } catch (dbError) {
        console.error('Database operation failed:', dbError);
        return res.status(500).json({
          success: false,
          message: 'Database operation failed'
        });
      }
    } else {
      console.warn('Database not connected - skipping library operations');
    }

    res.json({
      success: true,
      message: 'Payment verified and game added to library',
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id
    });
  } catch (error) {
    console.error('Razorpay verification error:', error);
    res.status(500).json({ success: false, message: 'Internal server error' });
  }
});

// Add game to library endpoint
app.post('/api/library/add', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { gameId, downloadUrl } = req.body;

    if (!gameId || !downloadUrl) {
      return res.status(400).json({ message: 'Game ID and download URL are required' });
    }

    const game = await Game.findById(gameId);
    if (!game) {
      return res.status(404).json({ message: 'Game not found' });
    }

    let library = await Library.findOne({ userId });
    if (!library) {
      library = new Library({ userId, games: [] });
    }

    // Check if game already in library
    const exists = library.games.some(g => g.gameId.toString() === gameId);
    if (exists) {
      return res.status(400).json({ message: 'Game already in library' });
    }

    library.games.push({ gameId, title: game.title, downloadUrl });
    await library.save();

    res.json({ message: 'Game added to library', library });
  } catch (error) {
    console.error('Add to library error:', error);
    res.status(500).json({ message: 'Error adding game to library' });
  }
});

// Get user's library endpoint
app.get('/api/library', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    console.log('Fetching library for user:', userId);
    
    const library = await Library.findOne({ userId })
      .populate({
        path: 'games.gameId',
        model: 'Game',
        select: 'title image logo price description genre'
      });

    if (!library) {
      console.log('No library found for user');
      return res.json({ games: [] });
    }

    console.log('Found library:', library.games);
    res.json({ games: library.games });
  } catch (error) {
    console.error('Fetch library error:', error);
    res.status(500).json({ message: 'Error fetching library' });
  }
});

// Download game endpoint
app.get('/api/library/download/:gameId', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const { gameId } = req.params;

    const library = await Library.findOne({ userId });
    if (!library) {
      return res.status(404).json({ message: 'Library not found' });
    }

    const gameEntry = library.games.find(g => g.gameId.toString() === gameId);
    if (!gameEntry) {
      return res.status(404).json({ message: 'Game not found in library' });
    }

    // For simplicity, return the download URL and a file name
    const fileName = gameEntry.title.replace(/\s+/g, '_') + '.zip'; // Assuming zip file

    res.json({ downloadUrl: gameEntry.downloadUrl, fileName });
  } catch (error) {
    console.error('Download game error:', error);
    res.status(500).json({ message: 'Error processing download' });
  }
});

// Routes

// Log all incoming requests for debugging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Razorpay payment verification endpoint
app.post('/api/razorpay/verify', async (req, res) => {
  try {
    console.log('Payment verification request received:', {
      body: req.body,
      headers: req.headers,
      url: req.url,
      method: req.method
    });
    
    const { 
      razorpay_payment_id, 
      razorpay_order_id, 
      razorpay_signature,
      gameId
    } = req.body;

    console.log('Extracted payment details:', {
      razorpay_payment_id,
      razorpay_order_id,
      razorpay_signature,
      gameId
    });
    
    if (!razorpay_payment_id || !razorpay_order_id || !razorpay_signature || !gameId) {
      console.error('Missing parameters in webhook:', req.body);
      return res.status(400).json({ 
        success: false, 
        message: 'Missing payment verification parameters' 
      });
    }

    // Verify signature
    if (process.env.RAZORPAY_KEY_SECRET) {
      // crypto is imported at the top of the file
      const generated_signature = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
        .update(razorpay_order_id + '|' + razorpay_payment_id)
        .digest('hex');

      console.log('Signature verification:', {
        generated: generated_signature,
        received: razorpay_signature
      });

      if (generated_signature !== razorpay_signature) {
        return res.status(400).json({
          success: false,
          message: 'Invalid payment signature'
        });
      }
    }

    // Validate gameId
    if (!gameId) {
      console.error('GameId is missing in the request');
      return res.status(400).json({
        success: false,
        message: 'GameId is required'
      });
    }

    // Log all games in the database for debugging
    console.log('Listing all games in database:');
    const allGames = await Game.find({}, '_id title');
    console.log('Available games:', allGames);

    // Try to find the game with flexible ID format
    console.log('Searching for game with ID:', gameId);
    let game;
    try {
      // Try direct ID first
      game = await Game.findById(gameId);
      
      // If not found, try searching without case sensitivity
      if (!game) {
        const games = await Game.find({});
        game = games.find(g => g._id.toString().toLowerCase() === gameId.toLowerCase());
      }
    } catch (error) {
      console.error('Error finding game:', error);
    }

    // If still not found, return error
    if (!game) {
      console.error('Game not found with ID:', gameId);
      return res.status(404).json({
        success: false,
        message: 'Game not found. Available IDs: ' + allGames.map(g => g._id).join(', ')
      });
    }

    console.log('Found game:', game);
    if (!game) {
      console.error('Game not found for ID:', gameId);
      return res.status(404).json({
        success: false,
        message: 'Game not found'
      });
    }
    
    console.log('Found game:', {
      title: game.title,
      id: game._id
    });

    // Find the order
    console.log('Searching for order:', razorpay_order_id);
    const order = await Order.findOne({ orderId: razorpay_order_id });
    
    let userId;
    if (!order) {
      console.log('Order not found in database, checking payment with Razorpay');
      if (!razorpay) {
        console.error('Razorpay not configured');
        return res.status(500).json({
          success: false,
          message: 'Payment service unavailable'
        });
      }

      try {
        const payment = await razorpay.payments.fetch(razorpay_payment_id);
        console.log('Razorpay payment details:', payment);
        
        // Create a new order since it doesn't exist
        const newOrder = new Order({
          orderId: razorpay_order_id,
          paymentId: razorpay_payment_id,
          gameId: gameId,
          status: 'completed',
          userId: payment.notes && payment.notes.userId ? payment.notes.userId : null
        });
        
        await newOrder.save();
        console.log('Created new order:', newOrder);
        userId = newOrder.userId;
      } catch (err) {
        console.error('Failed to fetch/create payment:', err);
        return res.status(500).json({
          success: false,
          message: 'Failed to verify payment'
        });
      }
    } else {
      console.log('Found existing order:', order);
      userId = order.userId;
    }

    if (!userId) {
      console.error('No userId found in order or payment');
      return res.status(400).json({
        success: false,
        message: 'User information missing'
      });
    }

    // Update user's library
    let library = await Library.findOne({ userId: order.userId });
    if (!library) {
      library = new Library({
        userId: order.userId,
        games: []
      });
    }

    // Add game if not already in library
    const gameExists = library.games.some(g => g.gameId.toString() === gameId);
    if (!gameExists) {
      library.games.push({
        gameId: game._id,
        title: game.title,
        downloadUrl: `/api/games/download/${game._id}`,
        addedAt: new Date()
      });
      await library.save();
      console.log('Game added to library:', game.title);
    }

    // Update order status
    order.status = 'completed';
    order.paymentId = razorpay_payment_id;
    await order.save();
    console.log('Order updated:', order);

    res.json({
      success: true,
      message: 'Payment verified and game added to library'
    });
  } catch (error) {
    console.error('Payment verification error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error during payment verification' 
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    message: 'Gaming Backend Server is running!',
    timestamp: new Date().toISOString(),
    status: 'healthy'
  });
});

// Epic Games News endpoint
// Epic Games news scraping removed (Puppeteer dependency removed)

// Razorpay order creation endpoint
app.post('/api/razorpay/order', authenticateToken, async (req, res) => {
  try {
    if (!razorpay) {
      return res.status(503).json({ message: 'Payment service unavailable' });
    }

    const { amount, currency = 'INR', receipt } = req.body;

    if (!amount || !receipt) {
      return res.status(400).json({ message: 'Amount and receipt are required' });
    }

    const options = {
      amount: amount * 100, // amount in the smallest currency unit (paise)
      currency,
      receipt,
      payment_capture: 1
    };

    const order = await razorpay.orders.create(options);

    res.json({
      success: true,
      order
    });
  } catch (error) {
    console.error('Razorpay order creation error:', error);
    res.status(500).json({ message: 'Error creating Razorpay order' });
  }
});

// Add a new game (Admin only)
app.post('/api/games', authenticateToken, async (req, res) => {
  try {
    // Removed admin-only check; any authenticated user can add games
    console.log('Add Game Request Body:', req.body); // Debug log
    const { title, description, image, price, genre, detailsJsonUrl } = req.body;
    if (!title || !description || !price) {
      return res.status(400).json({ message: 'Title, description, and price are required.' });
    }
    const newGame = new Game({ title, description, image, price, genre, detailsJsonUrl });
    await newGame.save();
    res.status(201).json({ message: 'Game added successfully', game: newGame });
  } catch (error) {
    console.error('Add game error:', error);
    res.status(500).json({ message: 'Error adding game' });
  }
});

// Get all games
app.get('/api/games', async (req, res) => {
  try {
    const games = await Game.find().sort({ createdAt: -1 });
    res.json({ games });
  } catch (error) {
    console.error('Fetch games error:', error);
    res.status(500).json({ message: 'Error fetching games' });
  }
});

// Update a game (Admin only)
app.put('/api/games/:id', authenticateToken, async (req, res) => {
  try {
    if (req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Admin access required' });
    }
    const { id } = req.params;
    const { title, description, image, price, genre } = req.body;
    const updated = await Game.findByIdAndUpdate(
      id,
      { title, description, image, price, genre },
      { new: true }
    );
    if (!updated) return res.status(404).json({ message: 'Game not found' });
    res.json({ message: 'Game updated', game: updated });
  } catch (error) {
    console.error('Update game error:', error);
    res.status(500).json({ message: 'Error updating game' });
  }
});

// Delete a game (Admin only)
app.delete('/api/games/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    console.log('Delete game request:', id, req.user);
    if (!mongoose.Types.ObjectId.isValid(id)) {
      return res.status(400).json({ message: 'Invalid game ID.' });
    }
    const deleted = await Game.findByIdAndDelete(id);
    if (!deleted) return res.status(404).json({ message: 'Game not found' });
    res.json({ message: 'Game deleted' });
  } catch (error) {
    console.error('Delete game error:', error);
    res.status(500).json({ message: 'Error deleting game' });
  }
});

// User Registration
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password, system_specs } = req.body;

    // Validate required fields
    if (!username || !email || !password || !system_specs) {
      return res.status(400).json({ 
        message: 'Username, email, password, and system specifications are required' 
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ 
        message: 'User with this email already exists' 
      });
    }

    // Validate system specs
    const requiredSpecs = ['os_version', 'RAM', 'graphics_card', 'disk'];
    for (let spec of requiredSpecs) {
      if (!system_specs[spec]) {
        return res.status(400).json({ 
          message: `${spec} is required in system specifications` 
        });
      }
    }

    // Validate processor (at least one should be selected)
    if (!system_specs.processor || 
        (!system_specs.processor.intel && !system_specs.processor.amd)) {
      return res.status(400).json({ 
        message: 'Please select either Intel or AMD processor' 
      });
    }

    // Hash password
    const saltRounds = 12;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Assign admin role if email matches (customize as needed)
    let role = 'user';
    if (email === 'admin@example.com') role = 'admin';

    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      system_specs,
      role
    });

    await newUser.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: newUser._id, 
        email: newUser.email,
        role: newUser.role
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser._id,
        username: newUser.username,
        email: newUser.email,
        system_specs: newUser.system_specs,
        createdAt: newUser.createdAt,
        role: newUser.role
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ 
      message: 'Internal server error during registration' 
    });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        message: 'Email and password are required' 
      });
    }

    // Find user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ 
        message: 'Invalid email or password' 
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        message: 'Invalid email or password' 
      });
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user._id, 
        email: user.email,
        role: user.role
      },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        system_specs: user.system_specs,
        lastLogin: user.lastLogin,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      message: 'Internal server error during login' 
    });
  }
});

// Forgot password - generate reset token (development: return token in response)
app.post('/api/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email is required' });
    // Try to find the user, but do not reveal whether the email exists in the response.
    const user = await User.findOne({ email });

    // If user exists, generate and store a reset token
    if (user) {
      const token = crypto.randomBytes(32).toString('hex');
      user.resetPasswordToken = token;
      user.resetPasswordExpires = Date.now() + (60 * 60 * 1000); // 1 hour
      await user.save();

      // Build reset link
      const frontendBase = process.env.FRONTEND_URL || 'http://localhost:5173';
      const resetLink = `${frontendBase}/reset-password?token=${token}&email=${encodeURIComponent(email)}`;

      // If SMTP configured, attempt to send email. If it fails, log the error but still return a generic success response.
      if (smtpIsConfigured()) {
        try {
          const html = `
            <p>Hi ${user.username || ''},</p>
            <p>You requested a password reset. Click the link below to reset your password. This link will expire in 1 hour.</p>
            <p><a href="${resetLink}">Reset your password</a></p>
            <p>If the link does not work you can also use the following reset token in the password reset form:</p>
            <pre style="background:#f4f4f4;padding:10px;border-radius:4px;overflow:auto">${token}</pre>
            <p>Or paste the following URL into your browser:</p>
            <p><a href="${resetLink}">${resetLink}</a></p>
            <p>If you did not request this, you can safely ignore this email.</p>
          `;

          await sendEmail(email, 'Password reset for your account', html);
          console.log('Password reset email sent to', email);
        } catch (emailErr) {
          console.error('Failed to send password reset email:', emailErr && emailErr.message ? emailErr.message : emailErr);
        }
      } else {
        // SMTP not configured: for security, do NOT return the token in the API response.
        console.warn('SMTP not configured - password reset token generated but email not sent for', email);
        // For local debugging you can find the token in server logs if needed.
        console.log('Password reset token for', email, ':', user.resetPasswordToken);
      }
    }

    // Always return a generic success message so callers cannot enumerate valid emails.
    res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ message: 'Error generating reset token' });
  }
});

// Reset password using token
app.post('/api/auth/reset', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ message: 'Token and newPassword are required' });

    const user = await User.findOne({ resetPasswordToken: token, resetPasswordExpires: { $gt: Date.now() } });
    if (!user) return res.status(400).json({ message: 'Invalid or expired token' });

    const saltRounds = 12;
    user.password = await bcrypt.hash(newPassword, saltRounds);
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    res.json({ message: 'Password has been reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ message: 'Error resetting password' });
  }
});

// Get User Profile (Protected Route)
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ 
        message: 'User not found' 
      });
    }

    res.json({
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        system_specs: user.system_specs,
        createdAt: user.createdAt,
        lastLogin: user.lastLogin
      }
    });

  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ 
      message: 'Error fetching user profile' 
    });
  }
});

// Update User System Specs (Protected Route)
app.put('/api/user/specs', authenticateToken, async (req, res) => {
  try {
    const { system_specs } = req.body;

    if (!system_specs) {
      return res.status(400).json({ 
        message: 'System specifications are required' 
      });
    }

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ 
        message: 'User not found' 
      });
    }

    // Update system specs
    user.system_specs = { ...user.system_specs, ...system_specs };
    await user.save();

    res.json({
      message: 'System specifications updated successfully',
      system_specs: user.system_specs
    });

  } catch (error) {
    console.error('Specs update error:', error);
    res.status(500).json({ 
      message: 'Error updating system specifications' 
    });
  }
});

// Cart API Endpoints

// Get user's cart
app.get('/api/cart', authenticateToken, async (req, res) => {
  try {
    let cart = await Cart.findOne({ userId: req.user.userId });
    if (!cart) {
      cart = { items: [], totalAmount: 0 };
    }
    res.json({ cart: cart });
  } catch (error) {
    console.error('Get cart error:', error);
    res.status(500).json({ message: 'Error fetching cart' });
  }
});

// Add item to cart
app.post('/api/cart/add', authenticateToken, async (req, res) => {
  try {
    const { gameId, title, price, image, logo, quantity = 1 } = req.body;
    
    if (!gameId || !title || !price) {
      return res.status(400).json({ message: 'Game ID, title, and price are required' });
    }

    let cart = await Cart.findOne({ userId: req.user.userId });
    
    if (!cart) {
      // Create new cart
      cart = new Cart({
        userId: req.user.userId,
        items: [{
          gameId,
          title,
          price: Number(price),
          image,
          logo,
          quantity: Number(quantity)
        }]
      });
    } else {
      // Check if item already exists in cart
      const existingItemIndex = cart.items.findIndex(item => item.gameId.toString() === gameId);
      
      if (existingItemIndex > -1) {
        // Update quantity
        cart.items[existingItemIndex].quantity += Number(quantity);
      } else {
        // Add new item
        cart.items.push({
          gameId,
          title,
          price: Number(price),
          image,
          logo,
          quantity: Number(quantity)
        });
      }
      cart.updatedAt = new Date();
    }
    
    await cart.save();
    res.json({ message: 'Item added to cart', cart });
  } catch (error) {
    console.error('Add to cart error:', error);
    res.status(500).json({ message: 'Error adding item to cart' });
  }
});

// Update cart item quantity
app.put('/api/cart/update', authenticateToken, async (req, res) => {
  try {
    const { gameId, quantity } = req.body;
    
    if (!gameId || quantity < 0) {
      return res.status(400).json({ message: 'Valid game ID and quantity are required' });
    }

    const cart = await Cart.findOne({ userId: req.user.userId });
    if (!cart) {
      return res.status(404).json({ message: 'Cart not found' });
    }

    if (quantity === 0) {
      // Remove item from cart
      cart.items = cart.items.filter(item => item.gameId.toString() !== gameId);
    } else {
      // Update quantity
      const itemIndex = cart.items.findIndex(item => item.gameId.toString() === gameId);
      if (itemIndex > -1) {
        cart.items[itemIndex].quantity = Number(quantity);
      } else {
        return res.status(404).json({ message: 'Item not found in cart' });
      }
    }
    
    cart.updatedAt = new Date();
    await cart.save();
    res.json({ message: 'Cart updated', cart });
  } catch (error) {
    console.error('Update cart error:', error);
    res.status(500).json({ message: 'Error updating cart' });
  }
});

// Remove item from cart
app.delete('/api/cart/remove/:gameId', authenticateToken, async (req, res) => {
  try {
    const { gameId } = req.params;
    
    const cart = await Cart.findOne({ userId: req.user.userId });
    if (!cart) {
      return res.status(404).json({ message: 'Cart not found' });
    }

    cart.items = cart.items.filter(item => item.gameId.toString() !== gameId);
    cart.updatedAt = new Date();
    await cart.save();
    
    res.json({ message: 'Item removed from cart', cart });
  } catch (error) {
    console.error('Remove from cart error:', error);
    res.status(500).json({ message: 'Error removing item from cart' });
  }
});

// Clear cart
app.delete('/api/cart/clear', authenticateToken, async (req, res) => {
  try {
    await Cart.findOneAndDelete({ userId: req.user.userId });
    res.json({ message: 'Cart cleared' });
  } catch (error) {
    console.error('Clear cart error:', error);
    res.status(500).json({ message: 'Error clearing cart' });
  }
});

// Purchase endpoint
app.post('/api/purchase', authenticateToken, async (req, res) => {
  try {
    const { gameId, paymentMethod } = req.body;
    const userId = req.user.userId;

    if (!gameId || !paymentMethod) {
      return res.status(400).json({ message: 'Game ID and payment method are required' });
    }

    // Validate game exists
    const game = await Game.findById(gameId);
    if (!game) {
      return res.status(404).json({ message: 'Game not found' });
    }

    // Validate user exists
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Generate unique order ID
    const orderId = `ORD-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    // Create order
    const order = new Order({
      userId,
      gameId,
      title: game.title,
      price: game.price,
      paymentMethod,
      orderId,
      status: 'pending'
    });

    await order.save();

    // For now, simulate payment gateway redirect
    // In real implementation, integrate with Stripe, PayPal, etc.
    const redirectUrl = `https://payment-gateway.com/pay?orderId=${orderId}&amount=${game.price}`;

    res.json({
      message: 'Order created successfully',
      order: {
        orderId,
        gameTitle: game.title,
        price: game.price,
        paymentMethod,
        status: 'pending',
        redirectUrl // Simulated
      }
    });
  } catch (error) {
    console.error('Purchase error:', error);
    res.status(500).json({ message: 'Error processing purchase' });
  }
});

// Get All Users (Admin endpoint - for testing)
app.get('/api/admin/users', async (req, res) => {
  try {
    const users = await User.find().select('-password');
    res.json({
      count: users.length,
      users
    });
  } catch (error) {
    console.error('Users fetch error:', error);
    res.status(500).json({ 
      message: 'Error fetching users' 
    });
  }
});

// System Stats endpoint
app.get('/api/stats/systems', async (req, res) => {
  try {
    const stats = await User.aggregate([
      {
        $group: {
          _id: null,
          totalUsers: { $sum: 1 },
          osVersions: { $push: '$system_specs.os_version' },
          ramSizes: { $push: '$system_specs.RAM' },
          graphicsCards: { $push: '$system_specs.graphics_card' }
        }
      }
    ]);

    if (stats.length === 0) {
      return res.json({ message: 'No users found' });
    }

    const result = stats[0];
    
    // Count occurrences
    const osCount = {};
    const ramCount = {};
    const gpuCount = {};

    result.osVersions.forEach(os => {
      osCount[os] = (osCount[os] || 0) + 1;
    });

    result.ramSizes.forEach(ram => {
      ramCount[ram] = (ramCount[ram] || 0) + 1;
    });

    result.graphicsCards.forEach(gpu => {
      gpuCount[gpu] = (gpuCount[gpu] || 0) + 1;
    });

    res.json({
      totalUsers: result.totalUsers,
      statistics: {
        operatingSystems: osCount,
        ramDistribution: ramCount,
        graphicsCards: gpuCount
      }
    });

  } catch (error) {
    console.error('Stats fetch error:', error);
    res.status(500).json({ 
      message: 'Error fetching system statistics' 
    });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ 
    message: 'Something went wrong!',
    error: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ 
    message: 'API endpoint not found' 
  });
});

// Start server
const startServer = async () => {
  await connectDB();
  app.listen(PORT, () => 
    console.log(`✅ Server running on http://localhost:${PORT}`)
  );
};

startServer().catch(console.error);

export default app;