const express = require("express");
const router = express.Router();

const controller = require("../controllers/device.controller");
const verifyToken = require("../middleware/verifyToken");
const checkRole = require("../middleware/checkRole");

router.post("/register", verifyToken, controller.registerDevice);

router.get(
  "/my-devices",
  verifyToken,
  checkRole("user_manager"),
  controller.getMyDevices
);

router.delete("/:device_id", verifyToken, controller.deleteDevice);

module.exports = router;
