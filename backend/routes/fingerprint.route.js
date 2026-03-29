const express = require("express");
const router = express.Router();

const controller = require("../controllers/fingerprint.controller");
const verifyToken = require("../middleware/verifyToken");

router.post("/enroll", verifyToken, controller.enrollFingerprint);

router.delete("/delete", verifyToken, controller.deleteFingerprint);

module.exports = router;
