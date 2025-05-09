const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const http = require("http");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const userRouter = require("./routes/userRouter");
const taskRouter = require("./routes/taskRouter");
const dashboardRouter = require("./routes/dashboardRouter");
const settingsRouter = require("./routes/settingsRouter");
const errorController = require("./src/controllers/errorController");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");

dotenv.config({ path: "./.env" });

const app = express(); // Express instance
const DB = process.env.DB_CONNECTION_STRING.replace(
  "<password>",
  process.env.DB_PASSWORD
);

// ================== ERROR HANDLING ==================

// Uncaught exceptions
process.on("uncaughtException", (err) => {
  console.log("UNCAUGHT EXCEPTION! 💥 Shutting down...");
  console.error(err.name, err.message);
  process.exit(1);
});

// ================== SECURITY MIDDLEWARES ==================

app.use(helmet()); // Set security headers
app.use(mongoSanitize()); // Prevent NoSQL injection
app.use(xss()); // Prevent XSS
app.use(hpp()); // Prevent parameter pollution

// ================== CORS CONFIG ==================
app.use(
  cors({
    origin: [
      "https://pract-9x4g.vercel.app", // ✅ Your Vercel frontend
      "http://localhost:5173", // ✅ Dev frontend
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    credentials: true, // ✅ Important for cookies/auth
  })
);

// ================== OTHER MIDDLEWARE ==================

app.use(express.json()); // Parse JSON
app.use(cookieParser()); // Parse cookies
app.use(bodyParser.urlencoded({ extended: true })); // Parse form data

// ================== ROUTES ==================

app.use("/api/users", userRouter);
app.use("/api/dashboard", dashboardRouter);
app.use("/api/tasks", taskRouter);
app.use("/api/settings", settingsRouter);

// Fallback for unmatched routes
app.use("*", (req, res) => {
  res.status(404).json({ message: "Not Found" });
});

// Global error handler
app.use(errorController);

// ================== DATABASE & SERVER ==================

mongoose
  .connect(DB, {})
  .then(() => {
    console.log("✅ MongoDB connected");

    const server = http.createServer(app);

    server.listen(process.env.PORT || 8080, () => {
      console.log(`🚀 Server running on port ${process.env.PORT || 8080}`);
    });

    // Unhandled Rejections
    process.on("unhandledRejection", (err) => {
      console.log("UNHANDLED REJECTION! 💥 Shutting down...");
      console.error(err.name, err.message);
      server.close(() => {
        process.exit(1);
      });
    });
  })
  .catch((err) => {
    console.error("❌ DATABASE CONNECTION ERROR:", err);
    process.exit(1);
  });

// ================== EXPORT ==================
module.exports = app;
