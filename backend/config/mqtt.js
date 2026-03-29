const mqtt = require("mqtt");
const AccessLog = require("../models/log.model");
const RFIDCard = require("../models/rfid.model");
const Fingerprint = require("../models/fingerprint.model");
const securityAlertService = require("../services/securityAlert.service");

class MQTTService {
  constructor() {
    this.client = null;
    this.isConnected = false;

    this.config = {
      broker: "6c6c58328eae454b8e3f8680129d7d32.s1.eu.hivemq.cloud",
      port: 8883,
      username: "smart_lock_nhom7_iot",
      password: "Nhom7iot",
      protocol: "mqtts",
    };

    // Topics
    this.topics = {
      // ESP32 → Backend
      ACCESS_LOG: "smartlock/access/log",
      ENROLL_RFID_RESULT: "smartlock/enroll/rfid",
      ENROLL_FP_RESULT: "smartlock/enroll/fingerprint/result",
      DELETE_FP_RESULT: "smartlock/delete/fingerprint/result",
      FACE_UNLOCK: "smartlock/sensor/face/unlock",
      STATUS: "smartlock/status",
    };
  }

  // ─── KẾT NỐI ────────────────────────────────────────────────────────────────

  connect(onConnected) {
    const url = `${this.config.protocol}://${this.config.broker}:${this.config.port}`;
    const options = {
      clientId: `backend_${Math.random().toString(16).slice(3)}`,
      username: this.config.username,
      password: this.config.password,
      clean: true,
      connectTimeout: 4000,
      reconnectPeriod: 1000,
    };

    console.log("Đang kết nối MQTT Broker...");
    this.client = mqtt.connect(url, options);

    this.client.on("connect", () => {
      console.log("✓ MQTT đã kết nối");
      this.isConnected = true;
      this.subscribeTopics();
      if (onConnected) onConnected();
    });

    this.client.on("message", (topic, message) => {
      this.handleMessage(topic, message);
    });

    this.client.on("error", (err) => {
      console.error("Lỗi MQTT:", err.message);
      this.isConnected = false;
    });

    this.client.on("close", () => {
      console.log("MQTT ngắt kết nối");
      this.isConnected = false;
    });
  }

  subscribeTopics() {
    const topics = [
      this.topics.ACCESS_LOG,
      this.topics.ENROLL_RFID_RESULT,
      this.topics.ENROLL_FP_RESULT,
      this.topics.DELETE_FP_RESULT,
      this.topics.FACE_UNLOCK,
      this.topics.STATUS,
    ];

    topics.forEach((t) => {
      this.client.subscribe(t, { qos: 1 }, (err) => {
        if (!err) console.log("✓ Subscribed:", t);
        else console.error("Lỗi subscribe:", t, err);
      });
    });
  }

  // ─── ROUTER ─────────────────────────────────────────────────────────────────

  handleMessage(topic, message) {
    try {
      const msg = message.toString();
      const data = JSON.parse(msg);
      console.log(`\n📨 [${topic}]`, JSON.stringify(data).slice(0, 120));

      switch (topic) {
        case this.topics.ACCESS_LOG:
          return this.handleAccessLog(data);

        case this.topics.ENROLL_RFID_RESULT:
          return this.handleEnrollRFIDResult(data);

        case this.topics.ENROLL_FP_RESULT:
          return this.handleEnrollFingerprintResult(data);

        case this.topics.DELETE_FP_RESULT:
          return this.handleDeleteFingerprintResult(data);

        case this.topics.FACE_UNLOCK:
          return this.handleFaceUnlock(data);

        default:
          break;
      }
    } catch (err) {
      console.error("Lỗi xử lý MQTT message:", err.message);
    }
  }

  // ─── HANDLER: LOG TỪ ESP32 ──────────────────────────────────────────────────
  // ESP32 tự quyết định mở/từ chối, sau đó publish log lên đây.

  async handleAccessLog(data) {
    const { device_id, access_method, result, user_id, reason, timestamp } =
      data;
    console.log(
      `📝 ACCESS LOG | ${access_method} | ${result} | device: ${device_id}`,
    );

    try {
      // Với RFID/vân tay: user_id đã được ESP32 gửi kèm
      let resolvedUserId = user_id || null;

      // Nếu là fingerprint và chỉ có fingerprintId thì lookup DB
      if (access_method === "fingerprint" && !user_id && data.fingerprintId) {
        const fp = await Fingerprint.findOne({
          fingerprint_id: String(data.fingerprintId),
        });
        if (fp) resolvedUserId = fp.user_id;
      }

      const log = await AccessLog.create({
        access_method,
        result: result || "failed",
        user_id: resolvedUserId,
        device_id: device_id || null,
        additional_info: reason || "",
      });

      console.log(`✓ Log đã lưu: ${log._id}`);

      // Cảnh báo brute-force nếu thất bại
      if (result === "failed" && device_id) {
        await securityAlertService.checkFailedAttempts(
          device_id,
          access_method,
        );
      }

      // Gửi realtime lên app
      if (global.io) {
        global.io.emit("access_log", {
          device_id,
          access_method,
          result,
          user_id: resolvedUserId,
          timestamp: new Date().toISOString(),
        });
      }
    } catch (err) {
      console.error("Lỗi lưu access log:", err.message);
    }
  }

  // ─── HANDLER: KẾT QUẢ ENROLL RFID ──────────────────────────────────────────
  // ESP32 đã lưu UID vào NVS, gửi kết quả lên để backend lưu DB.

  async handleEnrollRFIDResult(data) {
    // [FIX #3] Dùng "uid" thay vì "cardUid" cho khớp với model rfid đã cập nhật
    const { status, uid, userId, device_id, reason } = data;
    console.log(`💳 ENROLL RFID | ${status} | UID: ${uid} | User: ${userId}`);

    if (status === "success") {
      try {
        const existing = await RFIDCard.findOne({ uid });
        if (existing) {
          console.log("✗ UID đã tồn tại trong DB");
        } else {
          // [FIX #3] Bỏ trường card_id vì đã xoá khỏi model
          await RFIDCard.create({
            uid,
            user_id: userId,
            device_id,
          });
          console.log("✓ RFID đã lưu vào DB");
        }

        if (global.io) {
          global.io.to(`user_${userId}`).emit("rfid_enroll_result", {
            success: true,
            message: "Đăng ký thẻ RFID thành công!",
            uid,
            device_id,
          });
        }
      } catch (err) {
        console.error("Lỗi lưu RFID vào DB:", err.message);
      }
    } else {
      if (global.io && userId) {
        global.io.to(`user_${userId}`).emit("rfid_enroll_result", {
          success: false,
          message: reason || "Đăng ký thẻ thất bại",
          uid,
        });
      }
    }
  }

  // ─── HANDLER: KẾT QUẢ ENROLL VÂN TAY ───────────────────────────────────────

  async handleEnrollFingerprintResult(data) {
    const { status, fingerprintId, userId, device_id, reason } = data;
    console.log(
      `🔐 ENROLL FP | ${status} | ID: ${fingerprintId} | User: ${userId}`,
    );

    if (status === "success") {
      try {
        await Fingerprint.create({
          fingerprint_id: String(fingerprintId),
          user_id: userId,
          device_id: device_id,
        });
        console.log(`✓ Vân tay ${fingerprintId} đã lưu DB`);

        if (global.io) {
          global.io.to(`user_${userId}`).emit("fingerprint_enroll_result", {
            success: true,
            message: "Đăng ký vân tay thành công!",
            fingerprintId,
            device_id,
          });
        }
      } catch (err) {
        console.error("Lỗi lưu vân tay:", err.message);
      }
    } else {
      if (global.io && userId) {
        global.io.to(`user_${userId}`).emit("fingerprint_enroll_result", {
          success: false,
          message: reason || "Đăng ký vân tay thất bại",
          fingerprintId,
        });
      }
    }
  }

  // ─── HANDLER: KẾT QUẢ XOÁ VÂN TAY ─────────────────────────────────────────

  async handleDeleteFingerprintResult(data) {
    const { status, fingerprintId, userId, device_id, reason } = data;
    console.log(`🗑️ DELETE FP | ${status} | ID: ${fingerprintId}`);

    if (status === "success") {
      try {
        await Fingerprint.findOneAndDelete({
          fingerprint_id: String(fingerprintId),
          device_id,
        });
        console.log(`✓ Vân tay ${fingerprintId} đã xoá khỏi DB`);

        if (global.io && userId) {
          global.io.to(`user_${userId}`).emit("fingerprint_delete_result", {
            success: true,
            message: "Xoá vân tay thành công!",
            fingerprintId,
          });
        }
      } catch (err) {
        console.error("Lỗi xoá vân tay DB:", err.message);
      }
    } else {
      if (global.io && userId) {
        global.io.to(`user_${userId}`).emit("fingerprint_delete_result", {
          success: false,
          message: reason || "Xoá vân tay thất bại",
          fingerprintId,
        });
      }
    }
  }

  // ─── HANDLER: XÁC NHẬN MỞ KHOÁ FACE TỪ ESP32 ───────────────────────────────
  // ESP32 đã mở khoá, gửi xác nhận để backend lưu log.

  async handleFaceUnlock(data) {
    const { device_id, user_id, status } = data;
    const success = status === "valid";
    console.log(
      `👤 FACE UNLOCK | ${success ? "success" : "failed"} | User: ${user_id}`,
    );

    try {
      await AccessLog.create({
        access_method: "face",
        result: success ? "success" : "failed",
        user_id: user_id || null,
        device_id: device_id || null,
      });

      if (global.io && success) {
        global.io.emit("door_unlocked", {
          device_id,
          method: "face",
          user_id,
          timestamp: new Date().toISOString(),
        });
      }
    } catch (err) {
      console.error("Lỗi lưu face log:", err.message);
    }
  }

  // ─── PUBLISH ─────────────────────────────────────────────────────────────────

  publish(topic, payload, options = { qos: 1 }) {
    if (!this.isConnected) {
      console.error("MQTT chưa kết nối - không thể publish");
      return;
    }
    const msg = typeof payload === "string" ? payload : JSON.stringify(payload);
    this.client.publish(topic, msg, options, (err) => {
      if (err) console.error("Lỗi publish:", err.message);
    });
  }

  disconnect() {
    if (this.client) this.client.end();
  }
}

module.exports = new MQTTService();
