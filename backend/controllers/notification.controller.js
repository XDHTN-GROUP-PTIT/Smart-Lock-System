const Notification = require("../models/notification.model");
const Device = require("../models/device.model");
const AccessLog = require("../models/log.model");

//[GET] http://localhost:3000/notification - Lấy tất cả notification của user_manager
module.exports.getAllNotifications = async (req, res) => {
  try {
    const userId = req.user.id;

    // Đếm tổng số thông báo
    const total = await Notification.countDocuments({ user_id: userId });

    // Lấy toàn bộ notifications
    const notifications = await Notification.find({ user_id: userId })
      .sort({ created_at: -1 }) // mới nhất lên trước
      .lean();

    notifications.forEach((noti) => {
      if (noti.metadata && noti.metadata.alertPayload) {
        delete noti.metadata.alertPayload;
      }
    });

    // Đếm số chưa đọc
    const unreadCount = await Notification.countDocuments({
      user_id: userId,
      is_read: false,
    });

    return res.status(200).json({
      success: true,
      data: {
        total,
        unreadCount,
        notifications,
      },
    });
  } catch (error) {
    console.error("Lỗi lấy notifications:", error);
    return res.status(500).json({
      success: false,
      message: "Lỗi lấy danh sách thông báo",
    });
  }
};

// [DELETE] http://localhost:3000/notification/:notificationId - user_manager xóa một notification
module.exports.deleteNotification = async (req, res) => {
  try {
    const userId = req.user.id;
    const { notificationId } = req.params;

    const notification = await Notification.findOneAndDelete({
      _id: notificationId,
      user_id: userId,
    });

    if (!notification) {
      return res.status(404).json({
        success: false,
        message: "Không tìm thấy thông báo",
      });
    }

    return res.status(200).json({
      success: true,
      message: "Đã xóa thông báo",
    });
  } catch (error) {
    console.error("Lỗi xóa notification:", error);
    return res.status(500).json({
      success: false,
      message: "Lỗi xóa thông báo",
    });
  }
};

// [GET] http://localhost:3000/notification/statistics - Lấy thống kê cảnh báo bảo mật
module.exports.getAlertStatistics = async (req, res) => {
  try {
    const userId = req.user.id;
    const { days = 7 } = req.query;

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - parseInt(days));

    // Tổng số cảnh báo
    const totalAlerts = await Notification.countDocuments({
      user_id: userId,
      notification_type: "security_alert",
      created_at: { $gte: startDate },
    });

    // Cảnh báo chưa đọc
    const unreadAlerts = await Notification.countDocuments({
      user_id: userId,
      notification_type: "security_alert",
      is_read: false,
      created_at: { $gte: startDate },
    });

    // Thống kê theo thiết bị
    const alertsByDevice = await Notification.aggregate([
      {
        $match: {
          user_id: userId,
          notification_type: "security_alert",
          created_at: { $gte: startDate },
        },
      },
      {
        $group: {
          _id: "$metadata.deviceId",
          count: { $sum: 1 },
          deviceName: { $first: "$metadata.deviceName" },
          lastAlert: { $max: "$created_at" },
        },
      },
      {
        $sort: { count: -1 },
      },
    ]);

    // Thống kê theo ngày
    const alertsByDay = await Notification.aggregate([
      {
        $match: {
          user_id: userId,
          notification_type: "security_alert",
          created_at: { $gte: startDate },
        },
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$created_at" },
          },
          count: { $sum: 1 },
        },
      },
      {
        $sort: { _id: 1 },
      },
    ]);

    // Thiết bị có nhiều cảnh báo nhất
    const topAlertDevice = alertsByDevice[0] || null;

    return res.status(200).json({
      success: true,
      data: {
        period: `${days} ngày qua`,
        summary: {
          totalAlerts,
          unreadAlerts,
          readRate:
            totalAlerts > 0
              ? (((totalAlerts - unreadAlerts) / totalAlerts) * 100).toFixed(
                  1
                ) + "%"
              : "0%",
        },
        byDevice: alertsByDevice,
        byDay: alertsByDay,
        topAlertDevice,
      },
    });
  } catch (error) {
    console.error("Lỗi lấy statistics:", error);
    return res.status(500).json({
      success: false,
      message: "Lỗi lấy thống kê",
    });
  }
};
