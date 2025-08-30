const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Atlas Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log('MongoDB Atlas connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
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
  }
});

// Create User model
const User = mongoose.model('User', userSchema);

// JWT Middleware for protected routes
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

// Routes

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    message: 'Gaming Backend Server is running!',
    timestamp: new Date().toISOString(),
    status: 'healthy'
  });
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

    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      system_specs
    });

    await newUser.save();

    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: newUser._id, 
        email: newUser.email 
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
        createdAt: newUser.createdAt
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
        email: user.email 
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
        lastLogin: user.lastLogin
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      message: 'Internal server error during login' 
    });
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
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Health check: http://localhost:${PORT}/api/health`);
  });
};

startServer().catch(console.error);

module.exports = app;