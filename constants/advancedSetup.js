import { basicSetup } from "./basicSetup.js";

export const advancedSetup = {
  folders: [...basicSetup.folders, "uploads"],

  files: {
    ...basicSetup.files,
    "middlewares/auth.middleware.js": `
      const jwt = require("jsonwebtoken");
  
  exports.isLoggedIn = async (req, res, next) => {
    try {
      // get the accessToken from headers
      const accessToken = req.headers.authorization?.split(" ")[1];
      if (!accessToken) {
        return res.status(401).json({
          success: false,
          message: "You are not authorized to access this resource.",
        });
      }
  
      const decoded = jwt.verify(accessToken, process.env.ACCESS_TOKEN_SECRET);
      req.user = decoded;
  
      next();
    } catch (error) {
      return res.status(401).json({
        success: false,
        message: "Invalid or expired token. Please log in again.",
      });
    }
  };
  
  exports.isAdmin = async (req, res, next) => {
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "You are not authorized to access this resource.",
      });
    }
    next();
  };
  
      
      `,
    "controllers/auth.controller.js": `
  const bcrypt = require("bcryptjs");
  const sendEmail = require("../utils/sendEmail");
  const sendSMS = require("../utils/sendSMS");
  const cookieOptions = require("../constants/cookieOptions");
  const User = require("../models/user.model");
  const { OAuth2Client } = require("google-auth-library");
  const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  
  exports.signup = async (req, res) => {
    try {
      const { name, email, phoneNumber, password, role } = req.body;
  
      const existingUser = await User.findOne({
        $or: [{ email }, { phoneNumber }],
      });
  
      if (existingUser) {
        return res.status(400).json({
          success: false,
          message: "Email or phone number already in use.",
        });
      }
  
      const emailVerificationToken = Math.random().toString().slice(-4);
  
      const emailTokenExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
  
      const newUser = await User.create({
        name,
        email,
        phoneNumber,
        password,
        role,
        emailVerificationToken,
        emailTokenExpiry,
      });
  
      await sendEmail({
        to: email,
        subject: "Verify Your Email",
        text: "Your verification code is: __here__",
        html: "<p>Your verification code is: <strong>__here__</strong></p>",
      });
  
      const accessToken = await newUser.generateAccessToken();
      const refreshToken = await newUser.generateRefreshToken();
  
      res.cookie("refreshToken", refreshToken, cookieOptions);
      newUser.refreshToken.push(refreshToken);
  
      res.status(201).json({
        success: true,
        message:
          "User registered successfully. Please verify your email and phone number.",
        user: {
          _id: newUser._id,
          name: newUser.name,
          email: newUser.email,
          phoneNumber: newUser.phoneNumber,
          role: newUser.role,
          isEmailVerified: newUser.isEmailVerified,
        },
        accessToken,
      });
    } catch (error) {
      console.error("Signup Error:", error);
      res.status(500).json({
        success: false,
        message: "An error occurred during signup.",
      });
    }
  };
  
  exports.verfiyEmail = async (req, res) => {
    const { emailVerificationToken } = req.body;
    console.log("emailVerificationToken: ", emailVerificationToken);
    try {
      const user = await User.findOne({
        emailVerificationToken,
        emailTokenExpiry: { $gt: Date.now() },
      });
  
      if (!user) {
        return res.status(400).json({
          success: false,
          message: "Invalid verification token.",
        });
      }
  
      user.emailVerificationToken = null;
      user.emailTokenExpiry = null;
      user.isEmailVerified = true;
  
      await user.save();
  
      res.status(200).json({
        success: true,
        message: "Email verified successfully.",
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "An error occurred during email verification.",
      });
    }
  };
  
  exports.signin = async (req, res) => {
    const { email, password } = req.body;
    try {
      if (!email) {
        return res.status(400).json({
          success: false,
          message: "Email is required",
        });
      }
  
      const user = await User.findOne({ email }).select("+password");
  
      if (!user) {
        return res.status(400).json({
          success: false,
          message: 'No user found with this email',
        });
      }
  
      if (user.googleId) {
        return res.status(400).json({
          success: false,
          message: "Please sign in using Google.",
        });
      }
  
      const isPasswordValid = await user.comparePassword(password);
      console.log("Entered password:", password);
      console.log("Hashed password:", user.password);
      console.log("Is password valid?", isPasswordValid);
  
      if (!isPasswordValid) {
        return res.status(400).json({
          success: false,
          message: "Invalid credentials",
        });
      }
  
      const accessToken = await user.generateAccessToken();
      const refreshToken = await user.generateRefreshToken();
  
      res.cookie("refreshToken", refreshToken, cookieOptions);
      user.refreshToken.push(refreshToken);
  
      res.status(200).json({
        success: true,
        message: "User logged in successfully",
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          phoneNumber: user.phoneNumber,
          role: user.role,
          isEmailVerified: user.isEmailVerified,
          isPhoneNumberVerified: user.isPhoneNumberVerified,
        },
        accessToken,
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "An error occurred during login.",
        error: error.message,
      });
    }
  };
  exports.signout = async (req, res) => {
    try {
      res.clearCookie("refreshToken");
  
      res.status(200).json({
        success: true,
        message: "User logged out successfully",
      });
    } catch (error) {
      return res.status(500).json({
        success: false,
        message: "An error occurred during logout.",
      });
    }
  };
  
  exports.refreshToken = async (req, res) => {
    try {
      const { refreshToken } = req.body;
      if (!refreshToken) {
        return res.status(401).json({ message: "Refresh token is required" });
      }
  
      jwt.verify(
        refreshToken,
        process.env.REFRESH_TOKEN_SECRET,
        async (err, decoded) => {
          if (err) {
            return res
              .status(403)
              .json({ message: "Invalid or expired refresh token" });
          }
  
          const user = await User.findById(decoded.userId);
          if (!user) {
            return res.status(404).json({ message: "User not found" });
          }
  
          if (!user.refreshToken.includes(refreshToken)) {
            return res
              .status(403)
              .json({ message: "Refresh token is invalid or has been used" });
          }
  
          user.refreshToken = user.refreshToken.filter(
            (token) => token !== refreshToken
          );
  
          const newRefreshToken = user.generateRefreshToken();
          const newAccessToken = user.generateAccessToken();
  
          user.refreshToken.push(newRefreshToken);
          await user.save();
  
          res.json({
            accessToken: newAccessToken,
            refreshToken: newRefreshToken,
          });
        }
      );
    } catch (error) {
      res
        .status(500)
        .json({ message: "Internal server error", error: error.message });
    }
  };
  
  exports.googleAuth = async (req, res) => {
    try {
      const { credential } = req.body;
  
      if (!credential) {
        return res.status(400).json({ message: "Google credential is required" });
      }
  
      const ticket = await client.verifyIdToken({
        idToken: credential,
        audience: process.env.GOOGLE_CLIENT_ID,
      });
  
      const { email, name, picture, sub: googleId } = ticket.getPayload();
      let user = await User.findOne({ googleId });
  
      if (!user) {
        user = new User({
          name,
          email,
          googleId,
          profilePicture: { secure_url: picture },
          isEmailVerified: true,
        });
        await user.save();
      }
  
      const accessToken = user.generateAccessToken();
      const refreshToken = user.generateRefreshToken();
  
      user.refreshToken.push(refreshToken);
      await user.save();
  
      res.json({ accessToken, refreshToken, user });
    } catch (error) {
      res
        .status(500)
        .json({ message: "Google authentication failed", error: error.message });
    }
  };
  
  `,
    "controllers/user.controller.js": `
      const User = require("../models/user.model");
  
  exports.getAllUsers = async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
  
    try {
      const pageNum = parseInt(page) || 1;
      const limitNum = parseInt(limit) || 10;
      const skip = (pageNum - 1) * limitNum;
      const users = await User.find().skip(skip).limit(limitNum);
  
      const totalUsers = await User.countDocuments();
  
      res.status(200).json({
        success: true,
        users,
        totalUsers,
        totalPages: Math.ceil(totalUsers / limitNum),
      });
    } catch (error) {
      console.log("Error fetching all users, ", error);
    }
  };
  
  exports.getUserProfile = async (req, res) => {
    try {
      const user = await User.findById(req.user._id);
      res.status(200).json({ success: true, user });
    } catch (error) {
      console.log("Error fetching user profile, ", error);
    }
  };
      
      `,
    "routes/auth.routes.js": `
      const {
    signup,
    signin,
    signout,
    googleAuth,
    refreshToken,
    verfiyEmail,
  } = require("../controllers/auth.controller.js");
  
  const express = require("express");
  
  const router = express.Router();
  
  router.post("/google", googleAuth);
  router.post("/sign-up", signup);
  router.post("/verify-email", verfiyEmail);
  router.post("/sign-in", signin);
  router.get("/sign-out", signout);
  router.get("/refresh-token", refreshToken);
  
  module.exports = router;
  
      `,
    "routes/user.routes.js": `
      const {
    getAllUsers,
    getUserProfile,
    
    
  } = require("../controllers/user.controller.js");
  const { isLoggedIn } = require("../middlewares/auth.middleware.js");
  
  const express = require("express");
  const router = express.Router();
  
  router.get("/", getAllUsers);
  router.get("/me", isLoggedIn, getUserProfile);
  
  module.exports = router;
  
      `,
    "models/user.model.js": `
      const mongoose = require("mongoose");
  const bcrypt = require("bcryptjs");
  const jwt = require("jsonwebtoken");
  
  const roleEnum = {
    CUSTOMER: "customer",
    DRIVER: "driver",
    ADMIN: "admin",
  };
  
  const availabilityEnum = ["available", "unavailable"];
  
  const userSchema = new mongoose.Schema(
    {
      /*** Basic User Information ***/
      name: {
        type: String,
        required: true,
        trim: true,
      },
      email: {
        type: String,
        required: true,
        unique: true,
        match: [/\S+@\S+\.\S+/, "Please enter a valid email address"],
      },
      phoneNumber: {
        type: String,
        required: true,
        unique: true,
        index: true,
      },
      profilePicture: {
        public_id: String,
        secure_url: String,
      },
      role: {
        type: String,
        enum: Object.values(roleEnum),
        default: roleEnum.CUSTOMER,
      },
      /*** Location (GeoJSON format) ***/
      location: {
        type: { type: String, enum: ["Point"], default: "Point" },
        coordinates: { type: [Number], required: true, default: [0, 0] }, // [longitude, latitude]
      },
  
      /*** Authentication & Security ***/
      password: {
        type: String,
        select: false,
      },
      refreshToken: [String],
      googleId: String,
  
      /*** Email & Phone Verification ***/
      isEmailVerified: {
        type: Boolean,
        default: false,
      },
      emailVerificationToken: String,
      emailTokenExpiry: Date,
      isPhoneNumberVerified: {
        type: Boolean,
        default: false,
      },
      phoneNumberVerificationToken: String,
      phoneNumberTokenExpiry: Date,
  
      /*** Driver-Specific Fields ***/
      driverLicense: {
        number: String,
        expiry: Date,
        image: {
          public_id: String,
          secure_url: String,
        },
      },
      vehicleDetails: {
        type: String, // e.g., "Winch Truck"
        registrationNumber: String,
        registrationExpiry: Date,
        registrationImage: {
          public_id: String,
          secure_url: String,
        },
        capacity: {
          type: Number, // Weight capacity in KG
          required: false,
        },
      },
      availabilityStatus: {
        type: String,
        enum: availabilityEnum,
        default: "available",
      },
    },
    { timestamps: true }
  );
  
  /*** Hash Password Before Saving ***/
  userSchema.pre("save", async function (next) {
    if (!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
  });
  
  /*** Password Comparison ***/
  userSchema.methods.comparePassword = async function (candidatePassword) {
    if (!this.password) {
      console.error("Password is missing for user:", this._id);
      return false;
    }
    return await bcrypt.compare(candidatePassword, this.password);
  };
  
  /*** JWT Token Generation ***/
  userSchema.methods.generateAccessToken = function () {
    return jwt.sign(
      { userId: this._id, role: this.role },
      process.env.ACCESS_TOKEN_SECRET,
      {
        expiresIn: "1h",
      }
    );
  };
  
  userSchema.methods.generateRefreshToken = function () {
    return jwt.sign(
      { userId: this._id, role: this.role },
      process.env.REFRESH_TOKEN_SECRET,
      {
        expiresIn: "1d",
      }
    );
  };
  
  /*** Enable GeoJSON Index for Location Queries ***/
  userSchema.index({ location: "2dsphere" });
  
  const User = mongoose.model("User", userSchema);
  
  module.exports = User;
  
  
      `,
  },
};
