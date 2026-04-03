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
