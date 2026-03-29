const Device = require("../models/device.model");
const User = require("../models/user.model");
const Notification = require("../models/notification.model");
const Organization = require("../models/organization.model");

// [GET] http://localhost:3000/stats- Lấy thống kê cho user_manager
module.exports.getOverviewStats = async (req, res) => {
  try {
    const managerId = req.user.id;
    const orgId = req.user.org_id;

    // 1. Tổng số thiết bị mà user_manager sở hữu
    const totalDevices = await Device.countDocuments({ user_id: managerId });

    // 2. Tổng số user con
    const totalChildren = await User.countDocuments({
      parent_id: managerId,
      role: "user",
    });

    // 3. Tổng số cảnh báo bảo mật
    const totalSecurityAlerts = await Notification.countDocuments({
      user_id: managerId,
      notification_type: "security_alert",
    });

    // 4. Tổng số thông báo chưa đọc
    const unreadNotifications = await Notification.countDocuments({
      user_id: managerId,
      is_read: false,
    });

    //5. Thống kê số cảnh báo theo ngày
    const days = parseInt(req.query.days) || 7;

    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const dailyAlerts = await Notification.aggregate([
      {
        $match: {
          user_id: managerId,
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
      { $sort: { _id: 1 } },
    ]);

    const formattedDailyAlerts = dailyAlerts.map((i) => ({
      date: i._id,
      count: i.count,
    }));

    // 6. Thống kê theo từng device
    const devices = await Device.find({ user_id: managerId });
    const deviceStats = [];

    for (let device of devices) {
      const accessCount = await require("../models/log.model").countDocuments({
        device_id: device.device_id,
      });

      const alertCount = await Notification.countDocuments({
        "metadata.deviceId": device.device_id,
        notification_type: "security_alert",
      });

      deviceStats.push({
        device_id: device.device_id,
        device_name: device.model || device.type || "Unknown",
        status: device.status,
        total_access: accessCount,
        total_alerts: alertCount,
        last_seen: device.last_seen,
      });
    }

    // 7. Thống kê access log theo thời gian (today, week, month)
    const AccessLog = require("../models/log.model");
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    
    const monthAgo = new Date();
    monthAgo.setDate(monthAgo.getDate() - 30);

    const deviceIds = devices.map(d => d.device_id);

    const todayAccess = await AccessLog.countDocuments({
      device_id: { $in: deviceIds },
      createdAt: { $gte: today }
    });

    const weekAccess = await AccessLog.countDocuments({
      device_id: { $in: deviceIds },
      createdAt: { $gte: weekAgo }
    });

    const monthAccess = await AccessLog.countDocuments({
      device_id: { $in: deviceIds },
      createdAt: { $gte: monthAgo }
    });

    // 8. Recent access logs (10 gần nhất)
    const recentAccess = await AccessLog.find({
      device_id: { $in: deviceIds }
    })
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('user_id', 'fullName email')
      .lean();

    const formattedRecentAccess = recentAccess.map(log => {
      console.log('Log user_id:', log.user_id);
      console.log('User name:', log.user_id?.fullName);
      return {
        user_name: log.user_id?.fullName || "Unknown",
        device_id: log.device_id,
        timestamp: log.createdAt,
        access_method: log.access_method || "unknown",
        status: log.result || "success"
      };
    });

    // 9. Daily access count (7 ngày gần nhất)
    const dailyAccessData = await AccessLog.aggregate([
      {
        $match: {
          device_id: { $in: deviceIds },
          createdAt: { $gte: weekAgo }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    const formattedDailyAccess = dailyAccessData.map(i => ({
      date: i._id,
      count: i.count
    }));

    return res.json({
      code: 200,
      message: "Lấy thống kê thành công!",
      data: {
        totalDevices,
        totalChildren,
        totalSecurityAlerts,
        unreadNotifications,
        todayAccess,
        weekAccess,
        monthAccess,
        dailyAlerts: formattedDailyAlerts,
        dailyAccess: formattedDailyAccess,
        deviceStats,
        recentAccess: formattedRecentAccess
      },
    });
  } catch (err) {
    return res.status(500).json({
      code: 500,
      message: "Lỗi khi lấy thống kê!",
      error: err.message,
    });
  }
};

//[GET] http://localhost:3000/stats/admin - Lấy thống kê cho admin
module.exports.getAdminStats = async (req, res) => {
  try {
    // 1. Tổng số tổ chức
    const totalOrganizations = await Organization.countDocuments();

    // 2. Lấy thống kê từng tổ chức
    const orgStats = await Organization.aggregate([
      {
        $lookup: {
          from: "devices",
          localField: "_id",
          foreignField: "org_id",
          as: "devices",
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "org_id",
          as: "users",
        },
      },
      {
        $project: {
          org_id: "$_id",
          org_name: "$name",
          total_devices: { $size: "$devices" },
          total_user_manager: {
            $size: {
              $filter: {
                input: "$users",
                as: "u",
                cond: { $eq: ["$$u.role", "user_manager"] },
              },
            },
          },
        },
      },
    ]);

    // 3. Thêm thống kê số cảnh báo cho từng tổ chức
    for (let org of orgStats) {
      const deviceIds = await Device.find({ org_id: org.org_id }).distinct(
        "device_id"
      );

      org.total_alerts = await Notification.countDocuments({
        notification_type: "security_alert",
        "metadata.deviceId": { $in: deviceIds },
      });
    }

    // 4. Thống kê top 5 tổ chức có nhiều cảnh báo nhất
    const topOrganizations = [...orgStats]
      .sort((a, b) => b.total_alerts - a.total_alerts)
      .slice(0, 5);

    // 5. Thống kê cảnh báo theo ngày (toàn hệ thống)
    const days = parseInt(req.query.days) || 7;
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const dailyAlerts = await Notification.aggregate([
      {
        $match: {
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
      { $sort: { _id: 1 } },
    ]).then((results) =>
      results.map((i) => ({
        date: i._id,
        count: i.count,
      }))
    );

    // 6. Top 5 thiết bị có nhiều cảnh báo
    const topDevices = await Notification.aggregate([
      {
        $match: { notification_type: "security_alert" },
      },
      {
        $group: {
          _id: "$metadata.deviceId",
          count: { $sum: 1 },
        },
      },
      { $sort: { count: -1 } },
      { $limit: 5 },
    ]);

    return res.json({
      code: 200,
      message: "Thống kê admin thành công!",
      data: {
        totalOrganizations,
        organizations: orgStats,
        topOrganizations,
        dailyAlerts,
        topDevices,
      },
    });
  } catch (err) {
    return res.status(500).json({
      code: 500,
      message: "Lỗi khi lấy thống kê admin!",
      error: err.message,
    });
  }
};

//[GET] http://localhost:3000/stats/organization/:orgId - Admin lấy thống kê theo tổ chức
module.exports.getOrganizationStats = async (req, res) => {
  try {
    const { orgId } = req.params;
    const AccessLog = require("../models/log.model");

    // Verify organization exists
    const org = await Organization.findById(orgId);
    if (!org) {
      return res.status(404).json({
        code: 404,
        message: "Tổ chức không tồn tại!"
      });
    }

    // Get devices in this organization
    const devices = await Device.find({ org_id: orgId });
    const deviceIds = devices.map(d => d.device_id);

    // Time ranges
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const weekAgo = new Date();
    weekAgo.setDate(weekAgo.getDate() - 7);
    
    const monthAgo = new Date();
    monthAgo.setDate(monthAgo.getDate() - 30);

    // Count access logs
    const todayAccess = await AccessLog.countDocuments({
      device_id: { $in: deviceIds },
      createdAt: { $gte: today }
    });

    const weekAccess = await AccessLog.countDocuments({
      device_id: { $in: deviceIds },
      createdAt: { $gte: weekAgo }
    });

    const monthAccess = await AccessLog.countDocuments({
      device_id: { $in: deviceIds },
      createdAt: { $gte: monthAgo }
    });

    // Daily access data (7 days)
    const dailyAccessData = await AccessLog.aggregate([
      {
        $match: {
          device_id: { $in: deviceIds },
          createdAt: { $gte: weekAgo }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    const formattedDailyAccess = dailyAccessData.map(i => ({
      date: i._id,
      count: i.count
    }));

    // Recent access logs
    const recentAccess = await AccessLog.find({
      device_id: { $in: deviceIds }
    })
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('user_id', 'fullName email')
      .lean();

    const formattedRecentAccess = recentAccess.map(log => ({
      user_name: log.user_id?.fullName || "Unknown",
      device_id: log.device_id,
      timestamp: log.createdAt,
      access_method: log.access_method || "unknown",
      status: log.result || "success"
    }));

    // Device stats
    const deviceStats = [];
    for (let device of devices) {
      const accessCount = await AccessLog.countDocuments({
        device_id: device.device_id,
      });

      const alertCount = await Notification.countDocuments({
        "metadata.deviceId": device.device_id,
        notification_type: "security_alert",
      });

      deviceStats.push({
        device_id: device.device_id,
        device_name: device.model || device.type || "Unknown",
        status: device.status,
        total_access: accessCount,
        total_alerts: alertCount,
        last_seen: device.last_seen,
      });
    }

    // Count users
    const totalUserManagers = await User.countDocuments({
      org_id: orgId,
      role: "user_manager"
    });

    const totalUsers = await User.countDocuments({
      org_id: orgId,
      role: "user"
    });

    return res.json({
      code: 200,
      message: "Lấy thống kê tổ chức thành công!",
      data: {
        organization: {
          id: org._id,
          name: org.name,
          address: org.address
        },
        totalDevices: devices.length,
        totalUserManagers,
        totalUsers,
        todayAccess,
        weekAccess,
        monthAccess,
        dailyAccess: formattedDailyAccess,
        deviceStats,
        recentAccess: formattedRecentAccess
      },
    });
  } catch (err) {
    return res.status(500).json({
      code: 500,
      message: "Lỗi khi lấy thống kê tổ chức!",
      error: err.message,
    });
  }
};
