const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema({
  user_id: {
    type: String,
    required: true,
    index: true,
  },
  notification_type: {
    type: String,
    required: true,
    enum: [
      "security_alert", // ✅ Cảnh báo bảo mật
      "device_blocked", // Thiết bị bị khóa
      "device_online", // Thiết bị online
      "device_offline", // Thiết bị offline
      "system", // Thông báo hệ thống
      "other", // Khác
    ],
    index: true,
  },
  title: {
    type: String,
    required: true,
  },
  message: {
    type: String,
    required: true,
  },
  is_read: {
    type: Boolean,
    default: false,
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {},
  },
});

module.exports = mongoose.model("Notification", notificationSchema);
