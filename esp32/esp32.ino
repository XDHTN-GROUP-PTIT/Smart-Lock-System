/*
 * ========================================
 * ESP32 SMART LOCK - EMBEDDED VERSION
 * ========================================
 * Hệ thống khoá cửa thông minh chạy trên ESP32
 * - RFID: xác thực qua thẻ, lưu UID trong NVS
 * - Vân tay: xác thực qua AS608, lưu template trong chip
 * - Khuôn mặt: nhận lệnh mở khoá từ app qua MQTT
 * - Brute-force: tự động khoá 30s sau 3 lần thất bại
 * - MQTT: giao tiếp với backend qua HiveMQ cloud
 */

// ========================================
// LIBRARIES
// ========================================
#include <SPI.h>                    // Giao tiếp SPI (dùng cho RFID)
#include <MFRC522.h>                // Thư viện đầu đọc thẻ RFID MFRC522
#include <Adafruit_Fingerprint.h>   // Thư viện cảm biến vân tay AS608
#include <HardwareSerial.h>         // UART phần cứng (dùng cho AS608)
#include <WiFi.h>                   // Kết nối WiFi
#include <WiFiClientSecure.h>       // WiFi có TLS (dùng cho MQTT over SSL)
#include <PubSubClient.h>           // Thư viện MQTT client
#include <Preferences.h>            // Lưu dữ liệu vào NVS (bộ nhớ flash)

// ========================================
// CONFIGURATION
// ========================================

// --- WiFi ---
const char* ssid     = "LUCKY 32";
const char* password = "luckyhome@";

// --- MQTT Broker (HiveMQ Cloud) ---
const char* mqtt_server   = "6c6c58328eae454b8e3f8680129d7d32.s1.eu.hivemq.cloud";
const int   mqtt_port     = 8883;
const char* mqtt_user     = "smart_lock_nhom7_iot";
const char* mqtt_password = "Nhom7iot";

// --- Định danh thiết bị ---
const String device_id = "ESP32_SMARTLOCK_001";

// --- Chân GPIO ---
#define RELAY_PIN   14  // Relay điều khiển khoá điện từ
#define FINGER_RX   17  // UART RX nhận dữ liệu từ AS608
#define FINGER_TX   16  // UART TX gửi lệnh tới AS608
#define SS_PIN       2  // SPI Slave Select cho MFRC522
#define RST_PIN      4  // Reset cho MFRC522

// --- Thời gian (ms) ---
const unsigned long UNLOCK_DURATION      = 3000;  // Thời gian mở khoá (3 giây)
const unsigned long UNLOCK_COOLDOWN      = 5000;  // Thời gian chờ giữa 2 lần mở (5 giây)
const unsigned long CARD_DEBOUNCE_TIME   = 1000;  // Chống đọc thẻ trùng lặp (1 giây)
const unsigned long FINGERPRINT_INTERVAL = 2000;  // Chu kỳ quét vân tay (2 giây)
const unsigned long BRUTE_FORCE_LOCKOUT  = 30000; // Thời gian khoá khi bị tấn công (30 giây)
const int           FAIL_THRESHOLD       = 3;     // Số lần thất bại tối đa trước khi khoá

// --- NVS namespace ---
const char* NVS_NAMESPACE = "smartlock";  // Tên vùng nhớ NVS để lưu UID thẻ RFID

// ========================================
// MQTT TOPICS
// ========================================
// Topics ESP32 publish lên backend
const char* TOPIC_ACCESS_LOG         = "smartlock/access/log";                   // Gửi log mở/từ chối khoá
const char* TOPIC_ENROLL_RFID_RESULT = "smartlock/enroll/rfid";                  // Gửi kết quả đăng ký thẻ RFID
const char* TOPIC_ENROLL_FP_RESULT   = "smartlock/enroll/fingerprint/result";    // Gửi kết quả đăng ký vân tay
const char* TOPIC_DELETE_FP_RESULT   = "smartlock/delete/fingerprint/result";    // Gửi kết quả xoá vân tay
const char* TOPIC_STATUS             = "smartlock/status";                        // Gửi trạng thái khoá (locked/unlocked/online)

// ========================================
// GLOBAL OBJECTS
// ========================================
WiFiClientSecure     espClient;              // WiFi client có hỗ trợ TLS
PubSubClient         mqttClient(espClient);  // MQTT client dùng trên WiFi secure
HardwareSerial       fingerSerial(1);        // UART1 dành riêng cho AS608
Adafruit_Fingerprint finger(&fingerSerial);  // Đối tượng cảm biến vân tay
MFRC522              rfid(SS_PIN, RST_PIN);  // Đối tượng đầu đọc RFID
Preferences          prefs;                  // Đối tượng lưu trữ NVS

// ========================================
// STATE MACHINE
// ========================================
// Trạng thái hiện tại của khoá cửa
enum LockState { LOCKED, UNLOCKING, ALARM };
LockState lockState = LOCKED;               // Mặc định: đang khoá

unsigned long unlockStartTime = 0;   // Thời điểm bắt đầu mở khoá (để tự khoá lại sau UNLOCK_DURATION)
unsigned long lastUnlockTime  = 0;   // Thời điểm mở khoá lần cuối (để kiểm tra cooldown)

// ========================================
// BRUTE-FORCE PROTECTION
// ========================================
int  failCount        = 0;              // Số lần xác thực thất bại liên tiếp
bool bruteForceActive = false;          // Đang trong trạng thái khoá brute-force không
unsigned long bruteForceStartTime = 0;  // Thời điểm bắt đầu khoá brute-force

// ========================================
// ENROLLMENT STATE
// ========================================
// Trạng thái đăng ký thẻ RFID
bool   enrollingRFID          = false;  // Đang trong chế độ đăng ký thẻ không
String enrollingRFIDUserId    = "";     // User ID cần gắn với thẻ đang đăng ký

// Trạng thái đăng ký vân tay
bool   enrollingFingerprint       = false;   // Đang trong chế độ đăng ký vân tay không
String enrollingFingerprintUserId = "";
int    enrollingFingerprintId     = -1;

// ========================================
// RFID DEBOUNCE
// ========================================
String        lastCardUID  = "";   // UID của thẻ vừa quét (để chống đọc trùng)
unsigned long lastCardTime = 0;    // Thời điểm quét thẻ lần cuối

// ========================================
// SECTION 1: NVS - QUẢN LÝ UID HỢP LỆ
// ========================================
// Lưu danh sách UID thẻ RFID hợp lệ vào bộ nhớ flash (NVS)
// Key: "uid_XXXX", Value: userId tương ứng

// Khởi tạo NVS
void nvsBegin() {
  prefs.begin(NVS_NAMESPACE, false);
}

// Kiểm tra UID có tồn tại trong NVS không
bool isUIDValid(String uid) {
  String key = "uid_" + uid;
  return prefs.getString(key.c_str(), "").length() > 0;
}

// Lấy userId tương ứng với UID thẻ
String getUserIdByUID(String uid) {
  String key = "uid_" + uid;
  return prefs.getString(key.c_str(), "");
}

// Lưu UID và userId vào NVS
bool saveUID(String uid, String userId) {
  String key = "uid_" + uid;
  bool ok = prefs.putString(key.c_str(), userId.c_str());
  Serial.println(ok ? "✓ UID đã lưu NVS" : "✗ Lưu UID thất bại");
  return ok;
}

// Xoá một UID khỏi NVS
bool deleteUID(String uid) {
  String key = "uid_" + uid;
  bool ok = prefs.remove(key.c_str());
  Serial.println(ok ? "✓ UID đã xoá NVS" : "✗ Xoá UID thất bại");
  return ok;
}

// Xoá toàn bộ dữ liệu NVS (dùng khi xoá thiết bị khỏi hệ thống)
void clearAllUIDs() {
  prefs.clear();
  Serial.println("✓ Đã xoá toàn bộ UID trong NVS");
}

// ========================================
// SECTION 2: BRUTE-FORCE PROTECTION
// ========================================

// Ghi nhận một lần xác thực thất bại
// Nếu đủ FAIL_THRESHOLD lần → kích hoạt khoá brute-force và gửi cảnh báo lên backend
void recordFailedAttempt(String method) {
  failCount++;
  Serial.printf("⚠️ Thất bại lần %d/%d (method: %s)\n",
                failCount, FAIL_THRESHOLD, method.c_str());

  if (failCount >= FAIL_THRESHOLD) {
    bruteForceActive    = true;
    bruteForceStartTime = millis();
    lockState           = ALARM;
    Serial.println("🚨 BRUTE-FORCE DETECTED - Khoá " +
                   String(BRUTE_FORCE_LOCKOUT / 1000) + "s");

    // Gửi cảnh báo lên backend qua MQTT
    String alert = "{\"device_id\":\"" + device_id + "\","
                   "\"event\":\"brute_force_detected\","
                   "\"method\":\"" + method + "\","
                   "\"fail_count\":" + String(failCount) + ","
                   "\"timestamp\":" + String(millis()) + "}";
    mqttClient.publish(TOPIC_ACCESS_LOG, alert.c_str());
  }
}

// Reset bộ đếm thất bại (gọi sau khi mở khoá thành công)
void resetFailCount() { failCount = 0; }

// Kiểm tra có đang trong trạng thái khoá brute-force không
// Tự động mở khoá brute-force sau BRUTE_FORCE_LOCKOUT ms
bool isBruteForceLocked() {
  if (!bruteForceActive) return false;
  if (millis() - bruteForceStartTime >= BRUTE_FORCE_LOCKOUT) {
    bruteForceActive = false;
    failCount        = 0;
    lockState        = LOCKED;
    Serial.println("✓ Brute-force lockout hết hạn");
    return false;
  }
  return true;
}

// ========================================
// SECTION 3: HARDWARE CONTROL
// ========================================

// Forward declare để gọi trước khi định nghĩa
void publishAccessLog(String method, bool success,
                      String userId, String reason);

// Mở khoá cửa: bật relay, cập nhật state, gửi log lên backend
void openLock(String method, String userId) {
  // Bỏ qua nếu đang trong quá trình mở
  if (lockState == UNLOCKING) {
    Serial.println("⚠️ Đang mở khoá - Bỏ qua");
    return;
  }

  // Bỏ qua nếu chưa hết cooldown
  if (millis() - lastUnlockTime < UNLOCK_COOLDOWN) {
    Serial.println("⚠️ Cooldown - Chờ thêm");
    return;
  }

  Serial.println("🔓 MỞ KHOÁ | method: " + method + " | user: " + userId);
  lockState       = UNLOCKING;
  unlockStartTime = millis();
  lastUnlockTime  = millis();
  digitalWrite(RELAY_PIN, HIGH);  // Bật relay → mở khoá điện từ

  resetFailCount();
  publishAccessLog(method, true, userId, "");
  mqttClient.publish(TOPIC_STATUS, "{\"status\":\"unlocked\"}");
}

// Khoá cửa lại: tắt relay, cập nhật state, reset debounce RFID
void closeLock() {
  lockState = LOCKED;
  digitalWrite(RELAY_PIN, LOW);   // Tắt relay → khoá điện từ đóng lại
  mqttClient.publish(TOPIC_STATUS, "{\"status\":\"locked\"}");
  Serial.println("🔒 KHOÁ CỬA");

  // Reset debounce để lần quét thẻ tiếp theo không bị bỏ qua
  lastCardUID  = "";
  lastCardTime = 0;
}

// Từ chối truy cập: ghi nhận thất bại và gửi log lên backend
void denyAccess(String method, String reason) {
  Serial.println("✗ TỪ CHỐI | " + method + " | " + reason);
  recordFailedAttempt(method);
  publishAccessLog(method, false, "", reason);
}

// ========================================
// SECTION 4: PUBLISH HELPERS
// ========================================

// Gửi log truy cập lên backend qua MQTT topic ACCESS_LOG
void publishAccessLog(String method, bool success,
                      String userId, String reason) {
  String payload = "{\"device_id\":\"" + device_id + "\","
                   "\"access_method\":\"" + method + "\","
                   "\"result\":\"" + String(success ? "success" : "failed") + "\","
                   "\"user_id\":\"" + userId + "\","
                   "\"reason\":\"" + reason + "\","
                   "\"timestamp\":" + String(millis()) + "}";

  bool ok = mqttClient.publish(TOPIC_ACCESS_LOG, payload.c_str());
  Serial.println(ok ? "✓ Log gửi lên backend" : "⚠️ Gửi log thất bại (offline)");
}

// ========================================
// SECTION 5: RFID - LOGIC TRÊN CHIP
// ========================================

// Xử lý thẻ RFID khi đang ở chế độ bình thường (không enroll)
// Kiểm tra UID trong NVS → tự quyết định mở hoặc từ chối
void handleRFIDCard(String uid) {
  Serial.println("\n=== XỬ LÝ RFID ===");
  Serial.println("UID: " + uid);

// Không xử lý khi đang bị khoá brute-force
  if (isBruteForceLocked()) {
    unsigned long rem = BRUTE_FORCE_LOCKOUT - (millis() - bruteForceStartTime);
    Serial.printf("🚫 Brute-force lockout còn %.1fs\n", rem / 1000.0);
    return;
  }

  /// Tra cứu UID trong NVS - toàn bộ logic xử lý trên chip
  if (isUIDValid(uid)) {
    String userId = getUserIdByUID(uid);
    Serial.println("✓ UID hợp lệ - User: " + userId);
    openLock("rfid", userId);
  } else {
    Serial.println("✗ UID không tồn tại");
    denyAccess("rfid", "uid_not_found");
  }
}

// Xử lý thẻ RFID khi đang ở chế độ đăng ký (enrollingRFID = true)
// Lưu UID vào NVS rồi gửi kết quả lên backend
void handleEnrollRFIDCard(String uid) {
  Serial.println("💳 ENROLL RFID: " + uid + " | User: " + enrollingRFIDUserId);

  if (isUIDValid(uid)) {
    // UID đã tồn tại → báo thất bại
    String msg = "{\"status\":\"failed\",\"uid\":\"" + uid +
                 "\",\"userId\":\"" + enrollingRFIDUserId +
                 "\",\"device_id\":\"" + device_id +
                 "\",\"reason\":\"uid_already_exists\"}";
    mqttClient.publish(TOPIC_ENROLL_RFID_RESULT, msg.c_str());
    Serial.println("✗ UID đã tồn tại!");
  } else {
    // Lưu UID mới vào NVS → báo thành công để backend lưu vào DB
    saveUID(uid, enrollingRFIDUserId);
    String msg = "{\"status\":\"success\",\"uid\":\"" + uid +
                 "\",\"userId\":\"" + enrollingRFIDUserId +
                 "\",\"device_id\":\"" + device_id + "\"}";
    mqttClient.publish(TOPIC_ENROLL_RFID_RESULT, msg.c_str());
    Serial.println("✓ Enroll RFID thành công");
  }

  // Thoát chế độ enroll
  enrollingRFID       = false;
  enrollingRFIDUserId = "";
}

// ========================================
// SECTION 6: FINGERPRINT - LOGIC TRÊN CHIP
// ========================================

// Lấy ID vân tay từ AS608 (chip tự so khớp nội bộ)
// Trả về: fingerID (≥0) nếu khớp, -2 nếu không tìm thấy, -1 nếu lỗi/không có ngón tay
int getFingerprintID() {
  uint8_t p = finger.getImage();              // Chụp ảnh vân tay
  if (p == FINGERPRINT_NOFINGER) return -1;   // Không có ngón tay
  if (p != FINGERPRINT_OK)       return -1;   // Lỗi chụp ảnh

  p = finger.image2Tz();  // Chuyển ảnh thành template
  if (p != FINGERPRINT_OK) return -1;

  p = finger.fingerFastSearch();                          // AS608 tự tìm kiếm trong bộ nhớ nội bộ
  if (p == FINGERPRINT_OK)       return finger.fingerID;  // Tìm thấy → trả về ID
  if (p == FINGERPRINT_NOTFOUND) return -2;               // Không tìm thấy
  return -1;
}

// Xử lý kết quả so khớp vân tay
// AS608 tự so khớp, ESP32 nhận kết quả và quyết định mở hay từ chối
void handleFingerprintMatch(int fpId) {
  Serial.println("\n=== XỬ LÝ VÂN TAY ===");

  // Không xử lý khi đang bị khoá brute-force
  if (isBruteForceLocked()) {
    unsigned long rem = BRUTE_FORCE_LOCKOUT - (millis() - bruteForceStartTime);
    Serial.printf("🚫 Brute-force lockout còn %.1fs\n", rem / 1000.0);
    return;
  }

  if (fpId >= 0) {
    // AS608 xác nhận hợp lệ → ESP32 tự mở khoá, không cần hỏi server
    Serial.println("✓ VÂN TAY HỢP LỆ - ID: " + String(fpId));
    openLock("fingerprint", String(fpId));
  } else {
    Serial.println("✗ Vân tay không hợp lệ");
    denyAccess("fingerprint", "fingerprint_not_found");
  }
}

// Gửi kết quả đăng ký vân tay lên backend
void sendFingerprintEnrollResult(bool success, int id,
                                 String userId, String reason) {
  String msg = "{\"status\":\"" + String(success ? "success" : "failed") +
               "\",\"fingerprintId\":" + String(id) +
               ",\"userId\":\"" + userId +
               "\",\"device_id\":\"" + device_id + "\"";
  if (!success && reason.length() > 0)
    msg += ",\"reason\":\"" + reason + "\"";
  msg += "}";
  mqttClient.publish(TOPIC_ENROLL_FP_RESULT, msg.c_str());
}

// Thực hiện đăng ký vân tay từ xa (nhận lệnh qua MQTT)
// Quy trình: scan lần 1 → nhấc tay → scan lần 2 → tạo model → lưu vào AS608
void enrollFingerprintRemote(uint8_t id, String userId) {
  Serial.println("=== ĐĂNG KÝ VÂN TAY | ID: " + String(id) + " ===");
  uint8_t p = -1;
  unsigned long t;

  // --- Scan lần 1 ---
  Serial.println("Đặt ngón tay lên cảm biến...");
  t = millis();
  while (p != FINGERPRINT_OK) { 
    if (millis() - t > 15000) {   // Timeout 15 giây
      sendFingerprintEnrollResult(false, id, userId, "timeout_scan1");
      enrollingFingerprint = false; return;
    }
    p = finger.getImage();
    if (p == FINGERPRINT_NOFINGER) { delay(100); continue; }
    if (p != FINGERPRINT_OK) {
      sendFingerprintEnrollResult(false, id, userId, "image_error_scan1");
      enrollingFingerprint = false; return;
    }
  }
  if (finger.image2Tz(1) != FINGERPRINT_OK) {  // Chuyển ảnh 1 thành template slot 1
    sendFingerprintEnrollResult(false, id, userId, "convert_error_scan1");
    enrollingFingerprint = false; return;
  }

  // --- Nhấc ngón tay ---
  Serial.println("Nhấc ngón tay ra...");
  delay(2000);
  while (finger.getImage() != FINGERPRINT_NOFINGER) delay(100);

  // --- Scan lần 2 ---
  Serial.println("Đặt lại ngón tay...");
  p = -1; t = millis();
  while (p != FINGERPRINT_OK) {
    if (millis() - t > 15000) {  // Timeout 15 giây
      sendFingerprintEnrollResult(false, id, userId, "timeout_scan2");
      enrollingFingerprint = false; return;
    }
    p = finger.getImage();
    if (p == FINGERPRINT_NOFINGER) { delay(100); continue; }
    if (p != FINGERPRINT_OK) {
      sendFingerprintEnrollResult(false, id, userId, "image_error_scan2");
      enrollingFingerprint = false; return;
    }
  }
  if (finger.image2Tz(2) != FINGERPRINT_OK) { // Chuyển ảnh 2 thành template slot 2
    sendFingerprintEnrollResult(false, id, userId, "convert_error_scan2");
    enrollingFingerprint = false; return;
  }

  // --- Tạo model từ 2 lần scan ---
  p = finger.createModel();
  if (p == FINGERPRINT_ENROLLMISMATCH) {  // 2 lần scan không khớp nhau
    sendFingerprintEnrollResult(false, id, userId, "fingerprint_mismatch");
    enrollingFingerprint = false; return;
  }
  if (p != FINGERPRINT_OK) {
    sendFingerprintEnrollResult(false, id, userId, "model_error");
    enrollingFingerprint = false; return;
  }

  // --- Lưu model vào bộ nhớ AS608 ---
  p = finger.storeModel(id);
  if (p == FINGERPRINT_OK) {
    Serial.println("✓ Vân tay lưu thành công - ID: " + String(id));
    sendFingerprintEnrollResult(true, id, userId, "");   // Báo thành công → backend lưu DB
  } else {
    sendFingerprintEnrollResult(false, id, userId, "store_error");
  }

  // Reset RFID để tránh module bị treo sau khi enrollFingerprint blocking dài
  rfid.PCD_Init(); 
  delay(50);        

  enrollingFingerprint = false; // Thoát chế độ enroll
}

// Xoá toàn bộ vân tay trong chip AS608 (dùng khi xoá thiết bị)
void clearAllFingerprints() {
    uint8_t p = finger.emptyDatabase();  // Xoá toàn bộ template trong AS608
    Serial.println(p == FINGERPRINT_OK 
        ? "✓ Đã xóa toàn bộ vân tay AS608" 
        : "✗ Xóa vân tay thất bại: " + String(p));
}

// Xoá một vân tay theo ID trong AS608, gửi kết quả lên backend
void deleteFingerprintRemote(uint8_t id, String userId) {
  Serial.println("🗑️ XOÁ VÂN TAY ID: " + String(id));
  uint8_t p = finger.deleteModel(id);  // Xoá template khỏi AS608

  String msg = "{\"status\":\"" + String(p == FINGERPRINT_OK ? "success" : "failed") +
               "\",\"fingerprintId\":" + String(id) +
               ",\"userId\":\"" + userId +
               "\",\"device_id\":\"" + device_id + "\"";
  if (p != FINGERPRINT_OK)
    msg += ",\"reason\":\"delete_error_" + String(p) + "\"";
  msg += "}";
  mqttClient.publish(TOPIC_DELETE_FP_RESULT, msg.c_str());  // Báo kết quả → backend xoá DB
  Serial.println(p == FINGERPRINT_OK ? "✓ Xoá thành công" : "✗ Xoá thất bại");
}

// ========================================
// SECTION 7: MQTT CALLBACK
// ========================================
// Hàm xử lý tất cả các lệnh nhận từ backend qua MQTT
// Được gọi tự động mỗi khi có message đến

void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String topicStr = String(topic);
  String message  = "";
  for (unsigned int i = 0; i < length; i++) message += (char)payload[i];

  Serial.println("\n📨 MQTT: " + topicStr);
  Serial.println("   " + message);

  // --- Lệnh mở khoá từ app (khuôn mặt) ---
  // Backend gửi lệnh sau khi xác thực khuôn mặt thành công
  if (topicStr == "smartlock/device/" + device_id + "/control/unlock") {
    Serial.println("📱 Lệnh mở khoá từ app");

    // Parse userId từ JSON message
    String userId = "";
    int uS = message.indexOf("\"user_id\":\"") + 11;
    int uE = message.indexOf("\"", uS);
    if (uS > 10 && uE > uS) userId = message.substring(uS, uE);

    if (lockState != UNLOCKING) openLock("face", userId);

     // Gửi xác nhận ngược lại để backend lưu log
    if (userId.length() > 0) {
      String confirm = "{\"device_id\":\"" + device_id +
                       "\",\"status\":\"valid\",\"user_id\":\"" + userId +
                       "\",\"timestamp\":" + String(millis()) + "}";
      mqttClient.publish("smartlock/sensor/face/unlock", confirm.c_str());
    }
    return;
  }

  // --- Lệnh bắt đầu đăng ký thẻ RFID ---
  // Format: "ENROLL_RFID:{userId}"
  if (topicStr == "smartlock/device/" + device_id + "/enroll/rfid") {
    if (message.startsWith("ENROLL_RFID:")) {
      enrollingRFIDUserId = message.substring(12);
      enrollingRFID       = true;
      Serial.println("✓ Chế độ enroll RFID - User: " + enrollingRFIDUserId);
    }
    return;
  }

  // --- Lệnh xoá một thẻ RFID khỏi NVS ---
  // Format JSON: {"uid":"...","userId":"..."}
  if (topicStr == "smartlock/device/" + device_id + "/delete/rfid") {
    int uS = message.indexOf("\"uid\":\"") + 7;
    int uE = message.indexOf("\"", uS);
    if (uS > 6 && uE > uS) {
      String uid = message.substring(uS, uE);
      deleteUID(uid);  // Xoá UID khỏi NVS
    }
    return;
  }

  // --- Lệnh xoá toàn bộ dữ liệu khi device bị xoá khỏi hệ thống ---
  if (topicStr == "smartlock/device/" + device_id + "/clear") {
    Serial.println("🗑️ Nhận lệnh xoá device - Xoá NVS");
    clearAllUIDs();          // Xoá toàn bộ UID RFID trong NVS
    clearAllFingerprints();  // Xoá toàn bộ vân tay trong AS608
    return;
  }

  // --- Lệnh đăng ký vân tay ---
  // Format: "ENROLL_FINGERPRINT:{userId}:{fingerprintId}"
  if (topicStr == "smartlock/device/" + device_id + "/enroll/fingerprint") {
    if (message.startsWith("ENROLL_FINGERPRINT:")) {
      int c1 = message.indexOf(':');
      int c2 = message.indexOf(':', c1 + 1);
      enrollingFingerprintUserId = message.substring(c1 + 1, c2);      // Lấy userId
      enrollingFingerprintId     = message.substring(c2 + 1).toInt();  // Lấy fingerprintId
      enrollingFingerprint       = true;
      Serial.println("✓ Enroll vân tay | ID: " + String(enrollingFingerprintId));
      enrollFingerprintRemote(enrollingFingerprintId, enrollingFingerprintUserId);  // Bắt đầu quy trình đăng ký (blocking)
    }
    return;
  }

  // --- Lệnh xoá một vân tay ---
  // Format: "DELETE_FINGERPRINT:{userId}:{fingerprintId}"
  if (topicStr == "smartlock/device/" + device_id + "/delete/fingerprint") {
    if (message.startsWith("DELETE_FINGERPRINT:")) {
      int c1 = message.indexOf(':');
      int c2 = message.indexOf(':', c1 + 1);
      String userId = message.substring(c1 + 1, c2);
      int    fpId   = message.substring(c2 + 1).toInt();
      deleteFingerprintRemote(fpId, userId);  // Xoá template khỏi AS608 và báo backend
    }
    return;
  }
}

// ========================================
// SECTION 8: MQTT CONNECT
// ========================================

// Đăng ký nhận tất cả các topic lệnh từ backend
void subscribeTopics() {
  String base = "smartlock/device/" + device_id + "/";
  mqttClient.subscribe((base + "control/unlock").c_str());       // Mở khoá từ app
  mqttClient.subscribe((base + "enroll/rfid").c_str());          // Đăng ký RFID
  mqttClient.subscribe((base + "delete/rfid").c_str());          // Xoá RFID
  mqttClient.subscribe((base + "enroll/fingerprint").c_str());   // Đăng ký vân tay
  mqttClient.subscribe((base + "delete/fingerprint").c_str());   // Xoá vân tay
  mqttClient.subscribe((base + "clear").c_str());                // Xoá toàn bộ (khi device bị xoá)
  Serial.println("✓ Subscribed tất cả topics");
}

// Kết nối lại MQTT khi bị mất kết nối
void mqttReconnect() {
  while (!mqttClient.connected()) {
    Serial.print("Đang kết nối MQTT...");
    String clientId = "ESP32_" + String(random(0xffff), HEX);
    if (mqttClient.connect(clientId.c_str(), mqtt_user, mqtt_password)) {
      Serial.println(" ✓ OK");
      subscribeTopics();
      mqttClient.publish(TOPIC_STATUS, "{\"status\":\"online\"}");
    } else {
      Serial.printf(" ✗ rc=%d, thử lại 5s\n", mqttClient.state());
      delay(5000);
    }
  }
}

// ========================================
// SECTION 9: WIFI
// ========================================

// Kết nối WiFi, thử tối đa 40 lần (20 giây)
// Nếu thất bại vẫn chạy offline: RFID/vân tay hoạt động, MQTT không khả dụng
void setupWiFi() {
  Serial.println("Kết nối WiFi: " + String(ssid));
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  int attempt = 0;
  while (WiFi.status() != WL_CONNECTED && attempt < 40) {
    delay(500);
    Serial.print(".");
    attempt++;
  }
  Serial.println(); 

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("✓ WiFi kết nối thành công");
    Serial.println("  IP  : " + WiFi.localIP().toString());
    Serial.println("  RSSI: " + String(WiFi.RSSI()) + " dBm");
  } else {
    Serial.println("✗ WiFi kết nối THẤT BẠI sau " + String(attempt) + " lần thử");
    Serial.println("  Kiểm tra lại SSID/password hoặc vị trí thiết bị");
    Serial.println("  → Chạy OFFLINE: RFID/vân tay vẫn hoạt động qua NVS");
    Serial.println("  → MQTT và log sẽ không khả dụng");
  }
}

// ========================================
// SECTION 10: SETUP & LOOP
// ========================================

void setup() {
  // Khởi tạo relay ở trạng thái tắt (khoá đóng)
  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, LOW);

  Serial.begin(57600);
  delay(100);
  Serial.println("\n========== SMART LOCK BOOT ==========");

  // Khởi tạo NVS để lưu UID thẻ RFID
  nvsBegin();
  Serial.println("✓ NVS khởi tạo");

  // Kết nối WiFi
  setupWiFi();

  // Khởi tạo MQTT chỉ khi có WiFi
  if (WiFi.status() == WL_CONNECTED) {
    espClient.setInsecure();                        // Bỏ qua verify SSL certificate
    mqttClient.setBufferSize(2048);                 // Buffer đủ lớn cho payload JSON
    mqttClient.setServer(mqtt_server, mqtt_port);
    mqttClient.setCallback(mqttCallback);           // Đăng ký hàm xử lý message
    mqttClient.setKeepAlive(60);                    // Giữ kết nối 60 giây
  }

  // Khởi tạo cảm biến vân tay AS608 qua UART1
  fingerSerial.begin(57600, SERIAL_8N1, FINGER_RX, FINGER_TX);
  finger.begin(57600);
  delay(500);
  if (finger.verifyPassword()) {
    Serial.println("✓ AS608 sẵn sàng - " + String(finger.templateCount) + " vân tay");
  } else {
    Serial.println("✗ Không tìm thấy AS608!");
  }

  // Khởi tạo đầu đọc RFID MFRC522 qua SPI
  SPI.begin(18, 19, 23, SS_PIN);  // SCK=18, MISO=19, MOSI=23, SS=SS_PIN
  rfid.PCD_Init();
  Serial.println("✓ RFID sẵn sàng");

  Serial.println("========== BOOT HOÀN TẤT ==========\n");
}

void loop() {
  // --- Duy trì kết nối MQTT ---
  if (WiFi.status() == WL_CONNECTED) {
    if (!mqttClient.connected()) mqttReconnect();
    mqttClient.loop();
  }

  // --- Tự động khoá lại sau UNLOCK_DURATION ---
  if (lockState == UNLOCKING) {
    if (millis() - unlockStartTime >= UNLOCK_DURATION) {
      closeLock();  // Đủ thời gian → khoá lại
    }
    return; // Đang mở → không xử lý cảm biến
  }

  // --- Không xử lý cảm biến khi đang bị khoá brute-force ---
  if (isBruteForceLocked()) return;

  // --- Quét vân tay định kỳ mỗi FINGERPRINT_INTERVAL ms ---
  static unsigned long lastFPCheck = 0;
  if (millis() - lastFPCheck >= FINGERPRINT_INTERVAL) {
    lastFPCheck = millis();
    if (!enrollingFingerprint) {   // Không quét khi đang trong chế độ enroll
      int fpId = getFingerprintID();
      if (fpId >= 0)       handleFingerprintMatch(fpId);  // Tìm thấy vân tay
      else if (fpId == -2) handleFingerprintMatch(-2);    // Không khớp → từ chối
    }
  }

  // --- Quét RFID mỗi 300ms ---
  static unsigned long lastRFIDCheck = 0;
  if (millis() - lastRFIDCheck < 300) return;
  lastRFIDCheck = millis();

  if (!rfid.PICC_IsNewCardPresent()) return;  // Không có thẻ mới
  if (!rfid.PICC_ReadCardSerial()) {          // Đọc thẻ thất bại
    rfid.PICC_HaltA(); 
    rfid.PCD_StopCrypto1();
    return;
  }

  // Đọc và ghép UID từ các byte thành chuỗi hex viết hoa
  String uid = "";
  for (byte i = 0; i < rfid.uid.size; i++) {
    if (rfid.uid.uidByte[i] < 0x10) uid += "0";  // Đảm bảo 2 ký tự hex mỗi byte
    uid += String(rfid.uid.uidByte[i], HEX);
  }
  uid.toUpperCase();

  // Kết thúc giao tiếp với thẻ
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();

  // Debounce: bỏ qua nếu cùng UID quét lại quá nhanh
  // (lastCardUID được reset trong closeLock() nên sau khi khoá lại quét được ngay)
  if (uid == lastCardUID && (millis() - lastCardTime) < CARD_DEBOUNCE_TIME) {
    return;
  }
  lastCardUID  = uid;
  lastCardTime = millis();

  // Phân nhánh xử lý: đăng ký hay xác thực bình thường
  if (enrollingRFID) {
    handleEnrollRFIDCard(uid);  // Chế độ enroll: lưu UID mới
  } else {
    handleRFIDCard(uid);        // Chế độ bình thường: kiểm tra và mở khoá
  }

  // Cho MQTT xử lý thêm sau khi đọc thẻ (tránh mất message)
  for (int i = 0; i < 10; i++) {
    mqttClient.loop();
    delay(50);
  }
}
