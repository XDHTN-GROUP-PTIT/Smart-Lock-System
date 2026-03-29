const Device = require("../models/device.model");
const RFIDCard = require("../models/rfid.model");
const Fingerprint = require("../models/fingerprint.model");
const AccessLog = require("../models/log.model");
const mqttClient = require("../config/mqtt");

// [POST] /device/register - User_manager thêm thiết bị vào hệ thống
module.exports.registerDevice = async (req, res) => {
  try {
    const userId = req.user.id;
    const orgId = req.user.org_id;
    const { device_id, type, model } = req.body;

    if (!device_id || device_id.trim().length === 0) {
      return res
        .status(400)
        .json({ success: false, message: "device_id không được để trống" });
    }

    const existing = await Device.findOne({ device_id });
    if (existing) {
      return res
        .status(400)
        .json({ success: false, message: "Device ID đã tồn tại" });
    }

    const device = await Device.create({
      device_id,
      type: type || "smart_lock",
      model: model || "ESP32_v1",
      user_id: userId,
      org_id: orgId,
      status: "offline",
    });

    console.log("✓ Device đã thêm:", device_id);

    await AccessLog.create({
      access_method: "device_register",
      result: "success",
      device_id,
      user_id: userId,
      additional_info: "Device registered by user_manager",
    });

    res.json({
      success: true,
      message: "Đã thêm thiết bị thành công. Bật nguồn ESP32 để kết nối.",
      device_id,
    });
  } catch (err) {
    console.error("Lỗi registerDevice:", err.message);
    res
      .status(500)
      .json({ success: false, message: "Lỗi server: " + err.message });
  }
};

// [GET] /device/my-devices - Lấy thiết bị của user_manager
module.exports.getMyDevices = async (req, res) => {
  try {
    const devices = await Device.find({ user_id: req.user.id })
      .select("device_id type model status last_seen createdAt")
      .sort({ createdAt: -1 });

    res
      .status(200)
      .json({ success: true, count: devices.length, data: devices });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Lỗi server: " + err.message });
  }
};

// [DELETE] /device/:device_id - Xoá thiết bị
module.exports.deleteDevice = async (req, res) => {
  try {
    const { device_id } = req.params;
    const user = req.user;

    const device = await Device.findOne({ device_id });
    if (!device) {
      return res
        .status(404)
        .json({ success: false, message: "Device không tồn tại" });
    }

    // Kiểm tra quyền
    if (user.role !== "admin" && device.user_id.toString() !== user.id) {
      return res
        .status(403)
        .json({ success: false, message: "Không có quyền xoá device này" });
    }

    const clearTopic = `smartlock/device/${device_id}/clear`;
    mqttClient.publish(
      clearTopic,
      JSON.stringify({
        action: "clear_all",
        reason: "device_deleted",
      }),
    );
    console.log(`✓ Gửi lệnh clear NVS tới ${device_id}`);

    // Xoá RFID và vân tay liên quan
    await RFIDCard.deleteMany({ device_id });
    await Fingerprint.deleteMany({ device_id });
    await Device.deleteOne({ device_id });

    console.log(`✓ Device ${device_id} đã xoá`);

    await AccessLog.create({
      access_method: "device_deletion",
      result: "success",
      device_id,
      user_id: user.id,
      additional_info: `Xoá bởi ${user.role}`,
    });

    res.json({ success: true, message: "Xoá device thành công" });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Lỗi server: " + err.message });
  }
};
