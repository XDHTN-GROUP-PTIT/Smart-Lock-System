const express = require("express");
const router = express.Router();
const controller = require("../controllers/user.controller");
const validate = require("../validates/user.validate");
const verifyToken = require("../middleware/verifyToken");
const checkRole = require("../middleware/checkRole");

router.post("/register", verifyToken, checkRole("admin"), controller.register);

router.post("/login", validate.login, controller.login);

router.post("/logout", controller.logout);

router.get("/info", verifyToken, controller.info);

router.post(
  "/create",
  verifyToken,
  checkRole("user_manager", "admin"),
  controller.createUser,
);

router.get(
  "/children",
  verifyToken,
  checkRole("user_manager", "admin"),
  controller.getChildrenUsers,
);

router.delete(
  "/delete/:id",
  verifyToken,
  checkRole("user_manager", "admin"),
  controller.deleteUser,
);

router.patch(
  "/update",
  verifyToken,
  checkRole("user_manager", "admin"),
  controller.updateProfile,
);

module.exports = router;
