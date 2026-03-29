module.exports = (...allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        code: 403,
        message: "Bạn không có quyền truy cập chức năng này!",
      });
    }
    next();
  };
};
