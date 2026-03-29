const mongoose = require("mongoose");

const deviceSchema = new mongoose.Schema(
  {
    device_id: {
      type: String,
      required: true,
    },
    type: {
      type: String,
      trim: true,
      maxlength: 20,
    },
    model: {
      type: String,
      trim: true,
      maxlength: 100,
    },
    status: {
      type: String,
      enum: ["offline", "online", "blocked"],
      default: "offline",
    },
    user_id: {
      type: String,
      ref: "User",
      required: true,
    },
    org_id: {
      type: String,
      ref: "Organization",
    },
    last_seen: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: true,
    collection: "devices",
  },
);

module.exports = mongoose.model("Device", deviceSchema);
