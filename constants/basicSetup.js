export const basicSetup = {
  folders: [
    "models",
    "routes",
    "controllers",
    "__tests__",
    "middlewares",
    "utils",
    "config",
    "constants",
  ],
  files: {
    "server.js": `
  const express = require("express");
  const app = require("./app");
  
  const PORT = 5000;
  
  app.listen(PORT, () => {
      console.log('Server running on url http://localhost:5000');
  });
      `,

    "app.js": `
  const express = require("express");
  const helmet = require("helmet");
  const xss = require("xss-clean");
  const mongoSanitize = require("express-mongo-sanitize");
  const rateLimit = require("express-rate-limit");
  const hpp = require("hpp");
  const cors = require("cors");
  const userRoutes = require("./routes/user.routes");
  const authRoutes = require("./routes/auth.routes");
  const connectToDb = require("./config/db.config");
  const path = require("path");
  
  const app = express();
  const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100,
  });
  
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  
  // Routes
  app.use('/api/v1/auth', authRoutes);
  app.use("/api/v1/users", userRoutes);
  
  // Security
  app.use(helmet());
  app.use(xss());
  app.use(mongoSanitize());
  app.use(limiter);
  app.use(hpp());
  app.use(cors({
      origin: 'http://localhost:3000',
      credentials: true,
  }));
  
  app.use(express.static(path.join(__dirname, 'public')));
  
  connectToDb();
  
  module.exports = app;
      `,

    "config/db.config.js": `
  const mongoose = require("mongoose");
  
  exports.connectToDb = async () => {
    try {
      await mongoose.connect(process.env.MONGO_URI);
      console.log('MongoDB connected successfully');
    } catch (error) {
      console.log("MongoDB connection failed", error);
    }
  };
      `,
    ".env": `
      
      MONGO_URI=<mongo-uri>
  NODE_ENV=<env>
  
  COOKIE_SECRET=<your-cookie-secret>
  
  ACCESS_TOKEN_SECRET=<your-access-token-secret>
  REFRESH_TOKEN_SECRET=<your-refresh-token-secret>
  
  EMAIL_USER=<user-email>
  EMAIL_PASS=<app-password> # in case you're using gmail as your provider
  
  # Google oAuth
  GOOGLE_ClIENT_ID=<your-google-id>
  GOOGLE_CLIENT_SECRET=<your-google-secret>
  
  CLIENT_URL=<your-client-url>
      `,
  },
};
