const express = require("express");
const router = express.Router();

const controller = require("../controllers/log.controller");
const verifyToken = require("../middleware/verifyToken");
const checkRole = require("../middleware/checkRole");

router.get(
  "/:deviceId",
  verifyToken,
  checkRole("user_manager"),
  controller.getAllAccessLogs
);

module.exports = router;
