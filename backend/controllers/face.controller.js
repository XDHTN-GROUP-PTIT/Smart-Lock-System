const Device = require("../models/device.model");
const mqttClient = require("../config/mqtt");

// [POST] /face/unlock - Mở khoá bằng khuôn mặt (user_manager xác nhận từ app)
// Backend chỉ relay lệnh xuống ESP32, log sẽ được lưu khi ESP32 xác nhận
module.exports.unlockByFace = async (req, res) => {
  try {
    const userId = req.user.id;
    const { device_id } = req.body;

    if (!userId || !device_id) {
      return res
        .status(400)
        .json({ success: false, message: "Thiếu device_id" });
    }

    const device = await Device.findOne({ device_id });
    if (!device) {
      return res
        .status(404)
        .json({ success: false, message: "Thiết bị không tồn tại" });
    }

    // Relay lệnh mở khoá xuống ESP32
    const topic = `smartlock/device/${device_id}/control/unlock`;
    mqttClient.publish(topic, {
      action: "unlock",
      method: "face",
      user_id: userId,
      timestamp: new Date().toISOString(),
    });

    console.log(`✓ Relay lệnh face unlock tới ${device_id} cho user ${userId}`);

    res.json({
      success: true,
      message: "Đã gửi lệnh mở khoá",
      device_id,
      user_id: userId,
      timestamp: new Date().toISOString(),
    });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Lỗi server: " + err.message });
  }
};
