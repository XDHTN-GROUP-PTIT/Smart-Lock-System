const RFIDCard = require("../models/rfid.model");
const User = require("../models/user.model");
const AccessLog = require("../models/log.model");
const Device = require("../models/device.model");
const mqttClient = require("../config/mqtt");

//[GET] http://localhost:3000/log/:deviceId - Lấy ra danh sách log truy cập theo thiết bị
module.exports.getAllAccessLogs = async (req, res) => {
  try {
    const { deviceId } = req.params;

    if (!deviceId) {
      return res.status(400).json({
        success: false,
        message: "Thiếu deviceId!",
      });
    }

    const logs = await AccessLog.find({
      device_id: deviceId,
    })
      .sort({ createdAt: -1 })
      .populate("user_id", "fullName email role");

    return res.status(200).json({
      success: true,
      count: logs.length,
      data: logs,
    });
  } catch (error) {
    console.error("Lỗi lấy AccessLog:", error.message);
    return res.status(500).json({
      success: false,
      message: "Lỗi lấy AccessLog",
    });
  }
};
