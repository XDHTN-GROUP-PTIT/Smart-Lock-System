const RFIDCard = require("../models/rfid.model");
const Device = require("../models/device.model");
const mqttClient = require("../config/mqtt");

// [POST] /rfid/enroll - Gửi lệnh enroll RFID xuống ESP32
module.exports.enrollRFID = async (req, res) => {
  try {
    const { userId, device_id } = req.body;

    if (!userId || !device_id) {
      return res
        .status(400)
        .json({ success: false, message: "userId và device_id là bắt buộc" });
    }

    const device = await Device.findOne({ device_id });
    if (!device) {
      return res
        .status(404)
        .json({ success: false, message: "Thiết bị không tồn tại" });
    }

    // Gửi lệnh xuống ESP32 - ESP32 sẽ tự xử lý enroll và lưu vào NVS
    const topic = `smartlock/device/${device_id}/enroll/rfid`;
    mqttClient.publish(topic, `ENROLL_RFID:${userId}`);
    console.log(`✓ Gửi lệnh enroll RFID tới ${device_id} cho user ${userId}`);

    res.json({
      success: true,
      message: "Đã gửi lệnh. Hãy quét thẻ lên đầu đọc.",
      userId,
      device_id,
    });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Lỗi server: " + err.message });
  }
};

// [DELETE] /rfid/delete - Xoá thẻ RFID
// Xoá trong DB + gửi lệnh xuống ESP32 để xoá NVS
module.exports.deleteRFID = async (req, res) => {
  try {
    const { uid, userId } = req.body;

    if (!uid) {
      return res
        .status(400)
        .json({ success: false, message: "uid là bắt buộc" });
    }

    // Tìm thẻ trong DB
    const card = await RFIDCard.findOne({
      uid,
      ...(userId ? { user_id: userId } : {}),
    });

    if (!card) {
      return res
        .status(404)
        .json({ success: false, message: "Không tìm thấy thẻ RFID" });
    }

    // Gửi lệnh xoá UID xuống ESP32 để xoá khỏi NVS
    if (card.device_id) {
      const topic = `smartlock/device/${card.device_id}/delete/rfid`;
      // Gửi JSON với field "uid" cho khớp với firmware
      mqttClient.publish(
        topic,
        JSON.stringify({
          uid: card.uid,
          userId: card.user_id,
        }),
      );
      console.log(`✓ Gửi lệnh xoá UID ${card.uid} tới ${card.device_id}`);
    }

    // Xoá trong DB
    await RFIDCard.findByIdAndDelete(card._id);
    console.log(`✓ Đã xoá thẻ ${card.uid} khỏi DB`);

    res.json({
      success: true,
      message: "Xoá thẻ RFID thành công",
      data: {
        uid: card.uid,
        userId: card.user_id.toString(),
        deletedAt: new Date().toISOString(),
      },
    });
  } catch (err) {
    res
      .status(500)
      .json({ success: false, message: "Lỗi server: " + err.message });
  }
};
