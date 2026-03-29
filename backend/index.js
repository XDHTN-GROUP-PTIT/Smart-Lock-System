require("dotenv").config();
const express = require("express");
const http = require("http");
const socketIo = require("socket.io");
const cors = require("cors");
const bodyParser = require("body-parser");
const helmet = require("helmet");
const morgan = require("morgan");

const database = require("./config/database");
const mqttClient = require("./config/mqtt");
const route = require("./routes/index.route");

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS?.split(",") || "*",
    methods: ["GET", "POST"],
  },
});
global.io = io;

// Middleware
app.use(helmet());
app.use(
  cors({
    origin: process.env.ALLOWED_ORIGINS?.split(",") || "*",
    credentials: true,
  }),
);
app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));

// Health check
app.get("/health", (req, res) =>
  res.json({
    success: true,
    message: "Server is running",
    timestamp: new Date().toISOString(),
    mqtt: mqttClient.isConnected,
  }),
);

route(app);

// Socket.IO
io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);

  socket.on("authenticate", (data) => {
    if (data.userId) socket.join(`user_${data.userId}`);
    if (data.orgId) socket.join(`org_${data.orgId}`);
    if (data.role) socket.join(`role_${data.role}`);
  });

  socket.on("disconnect", () => console.log("Client disconnected:", socket.id));
});

// Start server
const PORT = process.env.PORT || 3000;

const startServer = async () => {
  try {
    await database.connect();

    mqttClient.connect();

    server.listen(PORT, () => {
      console.log(
        `Server running on port ${PORT} | Env: ${process.env.NODE_ENV || "development"}`,
      );
    });
  } catch (err) {
    console.error("Failed to start server:", err);
    process.exit(1);
  }
};

["SIGINT", "SIGTERM"].forEach((signal) =>
  process.on(signal, () => {
    server.close(() => {
      mqttClient.disconnect();
      process.exit(0);
    });
  }),
);

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
  process.exit(1);
});
process.on("unhandledRejection", (reason) => {
  console.error("Unhandled Rejection:", reason);
  process.exit(1);
});

startServer();

module.exports = { app, server, io };
