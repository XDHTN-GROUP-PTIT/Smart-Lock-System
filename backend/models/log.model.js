const mongoose = require("mongoose");

const logSchema = new mongoose.Schema(
  {
    access_method: {
      type: String,
      required: true,
      enum: [
        "rfid",
        "fingerprint",
        "face",
        "app",
        "device_register",
        "device_provision_init",
        "device_login",
        "device_deletion",
      ],
      trim: true,
    },
    result: {
      type: String,
      required: true,
      enum: ["success", "failed", "denied"],
      trim: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null,
    },
    device_id: {
      type: String,
      ref: "Device",
    },
    additional_info: {
      type: String,
      trim: true,
      default: "",
    },
  },
  {
    timestamps: true,
    collection: "access_logs",
  }
);

module.exports = mongoose.model("AccessLog", logSchema);
