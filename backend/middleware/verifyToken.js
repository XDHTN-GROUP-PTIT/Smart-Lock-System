const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET || "MY_SUPER_SECRET_KEY";

module.exports = function (req, res, next) {
  const token = req.headers.authorization?.split(" ")[1]; // Bearer <token>

  if (!token) {
    return res.status(401).json({
      code: 401,
      message: "Thiếu token! Hãy đăng nhập.",
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded; // gắn thông tin user vào request
    next();
  } catch (error) {
    res.status(401).json({
      code: 401,
      message: "Token không hợp lệ hoặc đã hết hạn!",
    });
  }
};
