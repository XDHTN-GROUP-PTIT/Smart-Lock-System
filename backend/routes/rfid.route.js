const express = require("express");
const router = express.Router();

const controller = require("../controllers/rfid.controller");
const verifyToken = require("../middleware/verifyToken");

router.post("/enroll", verifyToken, controller.enrollRFID);

router.delete("/delete", verifyToken, controller.deleteRFID);

module.exports = router;
