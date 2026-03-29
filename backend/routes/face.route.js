const express = require("express");
const router = express.Router();

const controller = require("../controllers/face.controller");
const verifyToken = require("../middleware/verifyToken");

router.post("/unlock", verifyToken, controller.unlockByFace);

module.exports = router;
