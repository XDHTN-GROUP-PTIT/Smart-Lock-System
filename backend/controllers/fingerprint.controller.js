const Fingerprint = require("../models/fingerprint.model");
const User = require("../models/user.model");
const Device = require("../models/device.model");
const mqttClient = require("../config/mqtt");

// [POST] /fingerprint/enroll - Gửi lệnh enroll vân tay xuống ESP32
module.exports.enrollFingerprint = async (req, res) => {
  try {
    const { user_id, device_id } = req.body;

    if (!user_id || !device_id) {
      return res
        .status(400)
        .json({ success: false, message: "user_id và device_id là bắt buộc" });
    }

    const user = await User.findById(user_id);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "Không tìm thấy user" });
    }

    const device = await Device.findOne({ device_id });
    if (!device) {
      return res
        .status(404)
        .json({ success: false, message: "Thiết bị không tồn tại" });
    }

    // Tìm fingerprint_id trống tiếp theo (1 - 127)
    let fingerprintId = null;
    for (let id = 1; id <= 127; id++) {
      const existing = await Fingerprint.findOne({
        fingerprint_id: String(id),
      });
      if (!existing) {
        fingerprintId = id;
        break;
      }
    }

    if (!fingerprintId) {
      return res
        .status(400)
        .json({ success: false, message: "Bộ nhớ vân tay đã đầy" });
    }

    // Gửi lệnh xuống ESP32
    const topic = `smartlock/device/${device_id}/enroll/fingerprint`;
    mqttClient.publish(topic, `ENROLL_FINGERPRINT:${user_id}:${fingerprintId}`);

    console.log(
      `✓ Gửi lệnh enroll vân tay tới ${device_id} | ID: ${fingerprintId}`,
    );

    res.json({
      success: true,
      message: "Đã gửi lệnh. Hãy đặt ngón tay lên cảm biến.",
      fingerprintId,
      user_id,
      device_id,
    });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Lỗi server: " + err.message });
  }
};

// [DELETE] /fingerprint/delete - Xoá vân tay
module.exports.deleteFingerprint = async (req, res) => {
  try {
    const { fingerprintId, userId, device_id } = req.body;

    if (!fingerprintId || !userId || !device_id) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Thiếu fingerprintId, userId hoặc device_id",
        });
    }

    const fp = await Fingerprint.findOne({
      fingerprint_id: String(fingerprintId),
      user_id: userId,
      device_id,
    });

    if (!fp) {
      return res
        .status(404)
        .json({ success: false, message: "Không tìm thấy vân tay" });
    }

    // Gửi lệnh xoá xuống ESP32 (AS608 tự xoá template)
    const topic = `smartlock/device/${device_id}/delete/fingerprint`;
    mqttClient.publish(topic, `DELETE_FINGERPRINT:${userId}:${fingerprintId}`, {
      qos: 1,
    });

    console.log(`✓ Gửi lệnh xoá vân tay ${fingerprintId} tới ${device_id}`);

    res.json({
      success: true,
      message: "Đã gửi lệnh xoá vân tay",
      fingerprintId,
      device_id,
    });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Lỗi server: " + err.message });
  }
};
