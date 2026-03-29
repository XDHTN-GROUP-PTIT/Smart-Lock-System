const express = require("express");
const router = express.Router();
const controller = require("../controllers/notification.controller");
const verifyToken = require("../middleware/verifyToken");
const checkRole = require("../middleware/checkRole");

// Lấy tất cả notification của user_manager
router.get(
  "/",
  verifyToken,
  checkRole("user_manager"),
  controller.getAllNotifications
);

// Xóa một notification
router.delete(
  "/:notificationId",
  verifyToken,
  checkRole("user_manager"),
  controller.deleteNotification
);

// Lấy thống kê cảnh báo
router.get(
  "/statistics",
  verifyToken,
  checkRole("user_manager"),
  controller.getAlertStatistics
);

module.exports = router;
