const express = require("express");
const router = express.Router();
const controller = require("../controllers/organization.controller");
const verifyToken = require("../middleware/verifyToken");
const checkRole = require("../middleware/checkRole");

router.get(
  "/",
  verifyToken,
  checkRole("admin"),
  controller.getOrganizations
);

router.post(
  "/create",
  verifyToken,
  checkRole("admin"),
  controller.createOrganization
);

router.delete(
  "/delete/:id",
  verifyToken,
  checkRole("admin"),
  controller.deleteOrganization
);

module.exports = router;
