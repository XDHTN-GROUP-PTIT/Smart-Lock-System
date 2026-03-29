const mongoose = require("mongoose");

const rfidCardSchema = new mongoose.Schema(
  {
    uid: {
      type: String,
      required: true,
    },
    createdAt: {
      type: Date,
      default: Date.now,
    },
    user_id: {
      type: String,
      ref: "User",
      required: true,
    },
    device_id: {
      type: String,
      required: false,
    },
  },
  {
    timestamps: true,
    collection: "rfid_cards",
  },
);

module.exports = mongoose.model("RFIDCard", rfidCardSchema);
