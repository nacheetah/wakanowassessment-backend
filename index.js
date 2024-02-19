const express = require("express");
const bodyParser = require("body-parser");
const cors = require('cors');
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const crypto = require('crypto');
const jwt = require("jsonwebtoken");

const app = express();
require('dotenv').config();

const PORT = process.env.PORT || 3000;

app.use(cors());

// MongoDB Connection
mongoose
  .connect("mongodb+srv://nacheetah70:mslalgebera@wakanow-cluster.ytcopkj.mongodb.net/?retryWrites=true&w=majority", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error(err));

// User Schema
const userSchema = new mongoose.Schema({
  first_name: String,
  last_name: String,
  email: String,
  password: String,
  temp_key: String,
  temp_key_expiry: Date,
  is_admin: Boolean,
  administrator: mongoose.Schema.Types.ObjectId, // Reference to admin user
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

app.use(bodyParser.json());

// Fetch All Users Endpoint
app.get("/", async (req, res) => {
  // const { userId } = req.user; // Retrieved from the JWT payload
  const { search } = req.query;

  try {
    let users;
    if (search) {
      // If search query is provided, filter users by email or name
      users = await User.find({
        $or: [
          { email: { $regex: search, $options: "i" } }, // Case-insensitive email search
          { first_name: { $regex: search, $options: "i" } }, // Case-insensitive first name search
          { last_name: { $regex: search, $options: "i" } }, // Case-insensitive last name search
        ],
      });
    } else {
      // If no search query provided, fetch all users
      users = await User.find();
    }

    // // Filter out non-admin users if the authenticated user is not an admin
    // if (!isAdmin) {
    //   users = users.filter((user) => user.is_admin);
    // }

    res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Sign-up Endpoint
app.post("/sign-up", async (req, res) => {
  try {
    const { first_name, last_name, email, password } = req.body;

    // Check if this is the first user in the database
    const isFirstUser = await User.countDocuments() === 0;

    // Set is_admin based on whether this is the first user
    const is_admin = isFirstUser ? true : false;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create new user
    const newUser = new User({
      first_name,
      last_name,
      email,
      password: hashedPassword,
      is_admin,
    });

    // Conditionally add temp_key and temp_key_expiry if this is the first user
    if (isFirstUser) {
      const tempKey = generateTempKey();
      const tempKeyExpiry = new Date(Date.now() + (7 * 24 * 60 * 60 * 1000)); // 1 week expiry

      newUser.temp_key = tempKey;
      newUser.temp_key_expiry = tempKeyExpiry;
    }

    await newUser.save();
    res.status(201).json({ message: "User created successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// Sign-in Endpoint
app.post("/sign-in", async (req, res) => {
  // Implementation of sign-in endpoint with JWT authentication
  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Check if password is correct
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Check if user is an admin and has a valid temp key
    if (!user.is_admin || !user.temp_key || user.temp_key_expiry < new Date()) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1h", // Token expires in 1 hour
    });

    res.status(200).json({ token, ...user._doc, password: undefined });
  } catch (error) {
    console.error("Error signing in:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Pending Users Endpoint
app.get("/pending", authenticateToken, async (req, res) => {
  const { userId } = req.user; // Retrieved from the JWT payload

  try {
    // Check if the authenticated user is an admin
    const adminUser = await User.findOne({ _id: userId, is_admin: true });
    if (!adminUser) {
      return res
        .status(403)
        .json({ message: "Only admins can access pending users" });
    }

    // Check if there are any users where the authenticated user's ID matches the administrator field
    const isAdministrator = await User.exists({ administrator: userId });
    if (isAdministrator) {
      // If the authenticated user is listed as an administrator for any user, handle the case accordingly
      return res.status(200).json([]);
    }
    
    // Find the earliest pending user (i.e., is_admin set to false and no temp_key) based on the date created
    const pendingUser = await User.findOne({
      is_admin: false,
      temp_key: null,
    }).sort({ createdAt: 1 });

    if (!pendingUser) {
      return res.status(404).json({ message: "No pending users found" });
    }

    res.status(200).json([pendingUser]);
  } catch (error) {
    console.error("Error fetching pending user:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Approve Endpoint
app.put("/approve/:user_id", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  const { userId } = req.user; // Retrieved from the JWT payload

  try {
    // Check if the authenticated user is an admin
    const adminUser = await User.findOne({ _id: userId, is_admin: true });
    if (!adminUser) {
      return res.status(403).json({ message: "Only admins can approve users" });
    }

    // Check if there are any users where the authenticated user's ID matches the administrator field
    const isAdministrator = await User.exists({ administrator: userId });
    if (isAdministrator) {
      // If the authenticated user is listed as an administrator for any user, handle the case accordingly
      return res.status(403).json({ message: "You are already an administrator" });
    }

    // Find the user to approve
    const userToApprove = await User.findById(user_id);
    if (!userToApprove) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if the user is already approved
    if (userToApprove.is_admin) {
      return res.status(400).json({ message: "User is already approved" });
    }

    // Set user as admin, generate temp key, and set expiry
    userToApprove.is_admin = true;
    userToApprove.temp_key = generateTempKey(); // Implement your own temp key generation logic
    userToApprove.temp_key_expiry = new Date(
      Date.now() + 7 * 24 * 60 * 60 * 1000
    ); // 1 week expiry
    userToApprove.administrator = userId; // Set the requesting user as the administrator

    // Save the updated user
    await userToApprove.save();

    res.status(200).json({ message: "User approved successfully" });
  } catch (error) {
    console.error("Error approving user:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Update Endpoint
app.put("/update/:user_id", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  const { userId } = req.user; // Retrieved from the JWT payload
  const { first_name, last_name, email, password } = req.body;

  try {
    // Find the user to update
    const userToUpdate = await User.findById(user_id);
    if (!userToUpdate) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if the authenticated user is an admin or the user to update
    if (
      !(
        userId === userToUpdate.administrator.toString() ||
        userId === userToUpdate._id.toString()
      )
    ) {
      return res.status(403).json({ message: "Unauthorized" });
    }

    // Update user details
    userToUpdate.first_name = first_name || userToUpdate.first_name;
    userToUpdate.last_name = last_name || userToUpdate.last_name;
    userToUpdate.email = email || userToUpdate.email;
    if (password) {
      // Hash and update password if provided
      const hashedPassword = await bcrypt.hash(password, 10);
      userToUpdate.password = hashedPassword;
    }

    // Save the updated user
    await userToUpdate.save();

    res.status(200).json({ message: "User details updated successfully" });
  } catch (error) {
    console.error("Error updating user details:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Delete Endpoint
app.delete("/delete/:user_id", authenticateToken, async (req, res) => {
  const { user_id } = req.params;
  const { userId } = req.user; // Retrieved from the JWT payload

  try {
    // Find the user to delete
    const userToDelete = await User.findById(user_id);
    if (!userToDelete) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if the authenticated user is an admin or the user to delete
    if (userId !== userToDelete.administrator.toString() || userId === userToDelete._id.toString()) {
      return res.status(400).json({ message: "Unauthorized" });

    }

    // Delete the user
    await User.deleteOne({ _id: user_id });

    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});



// GET user by ID endpoint
app.get('/:id', async (req, res) => {
  const userId = req.params.id;

  try {
    // Find the user by ID in the database
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json(user);
  } catch (error) {
    console.error('Error fetching user:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Check if Authorization header is present and extract token
  
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Forbidden" });
    }
    req.user = user;
    next();
  });
};

// Generate a random temporary key using crypto
function generateTempKey() {
  const tempKey = crypto.randomBytes(20).toString('hex');
  return tempKey;
};

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
