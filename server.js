// server.js - Updated with enhanced image handling
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const path = require("path");
const fs = require("fs");

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (images) with better error handling
app.use("/images", express.static(path.join(__dirname, "images")));

// Add a route to serve placeholder image for missing car images
app.get("/images/placeholder.jpg", (req, res) => {
  // If placeholder doesn't exist, create a simple SVG placeholder
  const placeholderSVG = `
    <svg width="400" height="300" xmlns="http://www.w3.org/2000/svg">
      <rect width="100%" height="100%" fill="#f0f0f0"/>
      <text x="50%" y="45%" text-anchor="middle" font-family="Arial" font-size="16" fill="#999">
        🚗
      </text>
      <text x="50%" y="60%" text-anchor="middle" font-family="Arial" font-size="12" fill="#999">
        Image Not Available
      </text>
    </svg>
  `;
  
  res.setHeader('Content-Type', 'image/svg+xml');
  res.send(placeholderSVG);
});

// Enhanced image serving route with fallback
app.get("/api/car-image/:imageName", (req, res) => {
  const imageName = req.params.imageName;
  const imagePath = path.join(__dirname, "images", imageName);
  
  // Check if image exists
  if (fs.existsSync(imagePath)) {
    res.sendFile(imagePath);
  } else {
    // Send placeholder if image doesn't exist
    const placeholderSVG = `
      <svg width="400" height="300" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="carGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:#667eea"/>
            <stop offset="100%" style="stop-color:#764ba2"/>
          </linearGradient>
        </defs>
        <rect width="100%" height="100%" fill="url(#carGradient)"/>
        <text x="50%" y="45%" text-anchor="middle" font-family="Arial, sans-serif" font-size="24" fill="white">
          🚗
        </text>
        <text x="50%" y="65%" text-anchor="middle" font-family="Arial, sans-serif" font-size="14" fill="white">
          ${imageName.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ').replace('.jpg', '')}
        </text>
      </svg>
    `;
    
    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'public, max-age=3600'); // Cache for 1 hour
    res.send(placeholderSVG);
  }
});

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI || "mongodb://localhost:27017/autosphere", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected successfully"))
  .catch((err) => console.error("MongoDB connection error:", err));

// ============ MODELS ============

// User Model
const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  password: {
    type: String,
    required: true,
  },
  favorites: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Car",
    },
  ],
  preferences: {
    priceRange: {
      min: Number,
      max: Number,
    },
    preferredMakes: [String],
    preferredFuelTypes: [String],
    preferredBodyTypes: [String],
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Enhanced Car Model with better image handling
const carSchema = new mongoose.Schema({
  make: {
    type: String,
    required: true,
  },
  model: {
    type: String,
    required: true,
  },
  year: {
    type: Number,
    required: true,
  },
  price: {
    type: Number,
    required: true,
  },
  mileage: {
    type: Number,
    required: true,
  },
  fuel: {
    type: String,
    enum: ["Petrol", "Diesel", "Hybrid", "Electric"],
    required: true,
  },
  transmission: {
    type: String,
    enum: ["Manual", "Automatic"],
    default: "Automatic",
  },
  bodyType: {
    type: String,
    enum: ["Sedan", "SUV", "Hatchback", "Coupe", "Truck", "Van"],
    default: "Sedan",
  },
  color: String,
  description: String,
  features: [String],
  images: [String], // Array of image filenames
  condition: {
    type: String,
    enum: ["New", "Used"],
    default: "Used",
  },
  location: String,
  seller: {
    name: String,
    phone: String,
    type: {
      type: String,
      enum: ["Dealer", "Private"],
      default: "Dealer",
    },
  },
  featured: {
    type: Boolean,
    default: false,
  },
  verified: {
    type: Boolean,
    default: false,
  },
  views: {
    type: Number,
    default: 0,
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

// Add virtual for primary image URL
carSchema.virtual('primaryImageUrl').get(function() {
  if (this.images && this.images.length > 0) {
    return `/api/car-image/${this.images[0]}`;
  }
  return '/api/car-image/placeholder.jpg';
});

// Add virtual for all image URLs
carSchema.virtual('imageUrls').get(function() {
  if (this.images && this.images.length > 0) {
    return this.images.map(img => `/api/car-image/${img}`);
  }
  return ['/api/car-image/placeholder.jpg'];
});

// Ensure virtuals are included in JSON output
carSchema.set('toJSON', { virtuals: true });
carSchema.set('toObject', { virtuals: true });

// Search History Model
const searchHistorySchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  query: String,
  filters: {
    make: String,
    priceRange: String,
    year: String,
    fuel: String,
  },
  timestamp: {
    type: Date,
    default: Date.now,
  },
});

// Recommendation Model
const recommendationSchema = new mongoose.Schema({
  user: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  car: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Car",
    required: true,
  },
  score: {
    type: Number,
    min: 0,
    max: 100,
  },
  reasons: [String],
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

const User = mongoose.model("User", userSchema);
const Car = mongoose.model("Car", carSchema);
const SearchHistory = mongoose.model("SearchHistory", searchHistorySchema);
const Recommendation = mongoose.model("Recommendation", recommendationSchema);

// ============ MIDDLEWARE ============

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Access token required" });
  }

  jwt.verify(
    token,
    process.env.JWT_SECRET || "your-secret-key",
    (err, user) => {
      if (err) {
        return res.status(403).json({ error: "Invalid or expired token" });
      }
      req.user = user;
      next();
    }
  );
};

// ============ ROUTES ============

// Health check
app.get("/api/health", (req, res) => {
  res.json({ status: "OK", message: "AutoSphere API is running" });
});

// ============ AUTH ROUTES ============

// Enhanced Registration endpoint with detailed logging
app.post("/api/auth/register", async (req, res) => {
  try {
    console.log("Registration attempt - Request body:", req.body);
    console.log("Registration attempt - Content-Type:", req.headers['content-type']);
    
    const { name, email, password } = req.body;

    // Enhanced validation with detailed error messages
    if (!name) {
      console.log("Registration failed: Missing name");
      return res.status(400).json({ error: "Name is required" });
    }
    
    if (!email) {
      console.log("Registration failed: Missing email");
      return res.status(400).json({ error: "Email is required" });
    }
    
    if (!password) {
      console.log("Registration failed: Missing password");
      return res.status(400).json({ error: "Password is required" });
    }

    if (password.length < 6) {
      console.log("Registration failed: Password too short");
      return res.status(400).json({ error: "Password must be at least 6 characters long" });
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      console.log("Registration failed: Invalid email format");
      return res.status(400).json({ error: "Please enter a valid email address" });
    }

    console.log("Checking if user exists with email:", email);

    // Check if user exists
    const existingUser = await User.findOne({ email: email.toLowerCase() });
    if (existingUser) {
      console.log("Registration failed: Email already registered");
      return res.status(400).json({ error: "Email already registered" });
    }

    console.log("Creating new user...");

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      name: name.trim(),
      email: email.toLowerCase().trim(),
      password: hashedPassword,
    });

    await user.save();
    console.log("User created successfully:", user._id);

    // Generate token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "7d" }
    );

    console.log("Registration successful for:", email);

    res.status(201).json({
      message: "User registered successfully",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Registration error - Full details:", error);
    
    // Handle specific MongoDB errors
    if (error.code === 11000) {
      console.log("Registration failed: Duplicate key error");
      return res.status(400).json({ error: "Email already registered" });
    }
    
    res.status(500).json({ 
      error: "Internal server error",
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Check password
    const isValidPassword = await bcrypt.compare(password, user.password);
    if (!isValidPassword) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id, email: user.email },
      process.env.JWT_SECRET || "your-secret-key",
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get current user
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password");
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(user);
  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ CAR ROUTES ============

// Get all cars with filters - Enhanced with image URLs
app.get("/api/cars", async (req, res) => {
  try {
    const {
      make,
      priceMin,
      priceMax,
      year,
      fuel,
      search,
      featured,
      page = 1,
      limit = 12,
    } = req.query;

    // Build query
    const query = {};

    if (make) query.make = make;
    if (year) query.year = parseInt(year);
    if (fuel) query.fuel = fuel;
    if (featured === "true") query.featured = true;

    if (priceMin || priceMax) {
      query.price = {};
      if (priceMin) query.price.$gte = parseInt(priceMin);
      if (priceMax) query.price.$lte = parseInt(priceMax);
    }

    if (search) {
      query.$or = [
        { make: { $regex: search, $options: "i" } },
        { model: { $regex: search, $options: "i" } },
      ];
    }

    // Pagination
    const skip = (page - 1) * limit;

    const cars = await Car.find(query)
      .skip(skip)
      .limit(parseInt(limit))
      .sort({ createdAt: -1 });

    const total = await Car.countDocuments(query);

    // Transform cars to include image URLs
    const carsWithImages = cars.map(car => {
      const carObj = car.toObject();
      return {
        ...carObj,
        primaryImageUrl: car.primaryImageUrl,
        imageUrls: car.imageUrls
      };
    });

    res.json({
      cars: carsWithImages,
      pagination: {
        current: parseInt(page),
        pages: Math.ceil(total / limit),
        total,
      },
    });
  } catch (error) {
    console.error("Get cars error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get single car - Enhanced with image URLs
app.get("/api/cars/:id", async (req, res) => {
  try {
    const car = await Car.findById(req.params.id);

    if (!car) {
      return res.status(404).json({ error: "Car not found" });
    }

    // Increment views
    car.views += 1;
    await car.save();

    // Transform car to include image URLs
    const carWithImages = {
      ...car.toObject(),
      primaryImageUrl: car.primaryImageUrl,
      imageUrls: car.imageUrls
    };

    res.json(carWithImages);
  } catch (error) {
    console.error("Get car error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get featured cars - Enhanced with image URLs
app.get("/api/cars/featured", async (req, res) => {
  try {
    const cars = await Car.find({ featured: true }).limit(6);
    
    const carsWithImages = cars.map(car => ({
      ...car.toObject(),
      primaryImageUrl: car.primaryImageUrl,
      imageUrls: car.imageUrls
    }));
    
    res.json(carsWithImages);
  } catch (error) {
    console.error("Get featured cars error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ FAVORITES ROUTES ============

// Get user favorites - Enhanced with image URLs
app.get("/api/favorites", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).populate("favorites");
    
    const favoritesWithImages = user.favorites.map(car => ({
      ...car.toObject(),
      primaryImageUrl: car.primaryImageUrl,
      imageUrls: car.imageUrls
    }));
    
    res.json(favoritesWithImages);
  } catch (error) {
    console.error("Get favorites error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Add to favorites
app.post("/api/favorites/:carId", authenticateToken, async (req, res) => {
  try {
    const { carId } = req.params;

    const user = await User.findById(req.user.userId);

    if (!user.favorites.includes(carId)) {
      user.favorites.push(carId);
      await user.save();
    }

    res.json({ message: "Added to favorites" });
  } catch (error) {
    console.error("Add favorite error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Remove from favorites
app.delete("/api/favorites/:carId", authenticateToken, async (req, res) => {
  try {
    const { carId } = req.params;

    await User.findByIdAndUpdate(req.user.userId, {
      $pull: { favorites: carId },
    });

    res.json({ message: "Removed from favorites" });
  } catch (error) {
    console.error("Remove favorite error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ RECOMMENDATIONS ROUTES ============

// Get personalized recommendations - Enhanced with image URLs
app.get("/api/recommendations", authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    const searchHistory = await SearchHistory.find({ user: user._id }).limit(
      10
    );

    // Simple recommendation algorithm based on user preferences and search history
    let query = {};

    if (user.preferences.preferredMakes?.length > 0) {
      query.make = { $in: user.preferences.preferredMakes };
    }

    if (user.preferences.priceRange) {
      query.price = {
        $gte: user.preferences.priceRange.min || 0,
        $lte: user.preferences.priceRange.max || 999999999,
      };
    }

    // Get cars matching preferences
    let recommendedCars = await Car.find(query).limit(6);

    // If not enough recommendations, get popular cars
    if (recommendedCars.length < 6) {
      const popularCars = await Car.find({ verified: true })
        .sort({ views: -1 })
        .limit(6 - recommendedCars.length);
      recommendedCars = [...recommendedCars, ...popularCars];
    }

    const recommendationsWithImages = recommendedCars.map(car => ({
      ...car.toObject(),
      primaryImageUrl: car.primaryImageUrl,
      imageUrls: car.imageUrls
    }));

    res.json(recommendationsWithImages);
  } catch (error) {
    console.error("Get recommendations error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Update user preferences
app.put("/api/user/preferences", authenticateToken, async (req, res) => {
  try {
    const { preferences } = req.body;

    await User.findByIdAndUpdate(
      req.user.userId,
      { preferences },
      { new: true }
    );

    res.json({ message: "Preferences updated successfully" });
  } catch (error) {
    console.error("Update preferences error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ SEARCH HISTORY ============

// Save search
app.post("/api/search/history", authenticateToken, async (req, res) => {
  try {
    const { query, filters } = req.body;

    const searchHistory = new SearchHistory({
      user: req.user.userId,
      query,
      filters,
    });

    await searchHistory.save();

    res.json({ message: "Search saved" });
  } catch (error) {
    console.error("Save search error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ============ ADMIN ROUTES (for testing) ============

// Enhanced seed with better image handling
app.post("/api/admin/seed", async (req, res) => {
  try {
    const sampleCars = [
      {
        make: "Toyota",
        model: "Camry",
        year: 2024,
        price: 125000,
        mileage: 15000,
        fuel: "Hybrid",
        transmission: "Automatic",
        bodyType: "Sedan",
        color: "Silver",
        description: "Well-maintained Toyota Camry with excellent fuel efficiency",
        features: ["Cruise Control", "Backup Camera", "Bluetooth", "Navigation"],
        images: ["toyota-camry-2024.jpg"],
        condition: "Used",
        location: "Dubai",
        seller: {
          name: "Al-Futtaim Toyota",
          phone: "+971-4-123-4567",
          type: "Dealer"
        },
        featured: true,
        verified: true,
      },
      {
        make: "Honda",
        model: "Accord",
        year: 2023,
        price: 115000,
        mileage: 20000,
        fuel: "Petrol",
        transmission: "Automatic",
        bodyType: "Sedan",
        color: "Black",
        description: "Spacious and reliable Honda Accord",
        features: ["Sunroof", "Leather Seats", "Apple CarPlay", "Android Auto"],
        images: ["honda-accord-2023.jpg"],
        condition: "Used",
        location: "Abu Dhabi",
        seller: {
          name: "Honda Abu Dhabi",
          phone: "+971-2-234-5678",
          type: "Dealer"
        },
        featured: true,
        verified: true,
      },
      {
        make: "Mercedes",
        model: "C-Class",
        year: 2024,
        price: 225000,
        mileage: 10000,
        fuel: "Petrol",
        transmission: "Automatic",
        bodyType: "Sedan",
        color: "White",
        description: "Luxury Mercedes-Benz C-Class with premium features",
        features: ["AMG Package", "Panoramic Roof", "Heated Seats", "Premium Sound"],
        images: ["mercedes-c-class-2024.jpg"],
        condition: "Used",
        location: "Dubai",
        seller: {
          name: "Mercedes-Benz Dubai",
          phone: "+971-4-345-6789",
          type: "Dealer"
        },
        featured: true,
        verified: true,
      },
      {
        make: "BMW",
        model: "3 Series",
        year: 2023,
        price: 195000,
        mileage: 18000,
        fuel: "Diesel",
        transmission: "Automatic",
        bodyType: "Sedan",
        color: "Blue",
        description: "Sporty BMW 3 Series with M Sport package",
        features: ["M Sport", "Heads-up Display", "Wireless Charging", "Parking Assist"],
        images: ["bmw-3-series-2023.jpg"],
        condition: "Used",
        location: "Sharjah",
        seller: {
          name: "BMW Sharjah",
          phone: "+971-6-456-7890",
          type: "Dealer"
        },
        featured: false,
        verified: true,
      },
      {
        make: "Nissan",
        model: "Altima",
        year: 2024,
        price: 95000,
        mileage: 5000,
        fuel: "Petrol",
        transmission: "Automatic",
        bodyType: "Sedan",
        color: "Red",
        description: "Efficient and comfortable Nissan Altima",
        features: ["ProPILOT Assist", "Remote Start", "Blind Spot Warning"],
        images: ["nissan-altima-2024.jpg"],
        condition: "Used",
        location: "Dubai",
        seller: {
          name: "Nissan Dubai",
          phone: "+971-4-567-8901",
          type: "Dealer"
        },
        featured: false,
        verified: true,
      },
      {
        make: "Toyota",
        model: "RAV4",
        year: 2023,
        price: 145000,
        mileage: 25000,
        fuel: "Hybrid",
        transmission: "Automatic",
        bodyType: "SUV",
        color: "Gray",
        description: "Versatile Toyota RAV4 hybrid SUV",
        features: ["All-Wheel Drive", "Trail Mode", "Cargo Space", "Safety Sense 2.0"],
        images: ["toyota-rav4-2023.jpg"],
        condition: "Used",
        location: "Dubai",
        seller: {
          name: "Al-Futtaim Toyota",
          phone: "+971-4-678-9012",
          type: "Dealer"
        },
        featured: true,
        verified: true,
      },
    ];

    // Clear existing cars
    await Car.deleteMany({});

    // Insert sample cars
    await Car.insertMany(sampleCars);

    res.json({
      message: "Database seeded successfully",
      count: sampleCars.length,
    });
  } catch (error) {
    console.error("Seed error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`AutoSphere API server running on port ${PORT}`);
  console.log(`API Documentation: http://localhost:${PORT}/api/health`);
  console.log(`Images served from: http://localhost:${PORT}/images/`);
  console.log(`Car images API: http://localhost:${PORT}/api/car-image/[filename]`);
});

// Function to seed database on startup (optional)
const seedDatabase = async () => {
  try {
    const carCount = await Car.countDocuments();

    if (carCount === 0) {
      console.log("Database is empty. Run the seeder to add sample data.");
      console.log("Use: node seeddata.js");
    } else {
      console.log(`Database contains ${carCount} cars`);
    }
  } catch (error) {
    console.error("Error checking database:", error);
  }
};

// Auto-check database on startup
mongoose.connection.once("open", async () => {
  await seedDatabase();
});
