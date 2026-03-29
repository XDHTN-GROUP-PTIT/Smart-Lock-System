const mongoose = require("mongoose");

const organizationSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100,
    },
    address: {
      type: String,
      trim: true,
      maxlength: 255,
    },
  },
  {
    timestamps: true,
    collection: "organizations",
  }
);

module.exports = mongoose.model("Organization", organizationSchema);
