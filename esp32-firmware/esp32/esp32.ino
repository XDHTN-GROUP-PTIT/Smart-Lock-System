/*
 * ============================================================
 * ESP32 SMART LOCK - EMBEDDED VERSION (IMPROVED)
 * ============================================================
 * Hệ thống khoá cửa thông minh chạy trên ESP32
 * - RFID: xác thực qua thẻ, lưu UID trong NVS Flash
 * - Vân tay: xác thực qua AS608, lưu template trong chip
 * - Khuôn mặt: nhận lệnh mở khoá từ app qua MQTT
 * - Brute-force: tự động khoá 30s sau 3 lần thất bại
 * - MQTT: giao tiếp với backend qua HiveMQ Cloud (TLS port 8883)
 * ============================================================
 */

// ============================================================
// LIBRARIES
// ============================================================
#include <SPI.h>                    // Giao tiếp SPI (dùng cho RFID MFRC522)
#include <MFRC522.h>                // Thư viện đầu đọc thẻ RFID MFRC522
#include <Adafruit_Fingerprint.h>   // Thư viện cảm biến vân tay AS608
#include <HardwareSerial.h>         // UART phần cứng ESP32 (dùng cho AS608)
#include <WiFi.h>                   // Kết nối WiFi 802.11 b/g/n (tích hợp ESP32)
#include <WiFiClientSecure.h>       // WiFi có TLS 1.2 (dùng cho MQTT over SSL)
#include <PubSubClient.h>           // Thư viện MQTT client (publish/subscribe)
#include <Preferences.h>            // Lưu dữ liệu key-value vào NVS Flash
#include <esp_task_wdt.h>           // [MỚI] Watchdog Timer ESP32 - Chương 3 trang 84

// ============================================================
// CONFIGURATION
// ============================================================

// --- WiFi ---
const char* ssid     = "LUCKY 32";
const char* password = "luckyhome@";

// --- MQTT Broker (HiveMQ Cloud) ---
const char* mqtt_server   = "6c6c58328eae454b8e3f8680129d7d32.s1.eu.hivemq.cloud";
const int   mqtt_port     = 8883;   // TLS port - mã hoá toàn bộ traffic
const char* mqtt_user     = "smart_lock_nhom7_iot";
const char* mqtt_password = "Nhom7iot";

// --- Định danh thiết bị ---
const String device_id = "ESP32_SMARTLOCK_001";

// ============================================================
// CHÂN GPIO - Giải thích theo tiêu chí chọn CPU 
// ============================================================
// Tiêu chí 1 - Ngoại vi cần kết nối: RFID(SPI), AS608(UART), Relay(GPIO)
// Tiêu chí 3 - Số ngắt cần: 1 ngắt ngoài cho RFID IRQ
// Tiêu chí 4 - Số cổng I/O: 7 chân (SPI×4 + UART×2 + GPIO×1)
// → ESP32 dual-core 240MHz đáp ứng đủ tất cả tiêu chí trên

#define RELAY_PIN    14  // GPIO14: OUTPUT điều khiển relay 5V (HIGH=mở, LOW=đóng)
                         // Lý do chọn GPIO14: chân SPI clock phụ, dùng được OUTPUT tự do
#define FINGER_RX    17  // UART1 RX: nhận dữ liệu từ AS608 (TX của AS608 nối vào đây)
#define FINGER_TX    16  // UART1 TX: gửi lệnh tới AS608 (RX của AS608 nối vào đây)
                         // Lý do dùng UART1 thay UART0: UART0 dùng cho Serial debug
#define SS_PIN        2  // SPI Slave Select cho MFRC522 (kéo LOW để chọn chip)
#define RST_PIN       4  // Reset MFRC522 (kéo LOW để reset, kéo HIGH để hoạt động)

// Chân IRQ của MFRC522 nối vào GPIO15
// MFRC522 sẽ kéo chân này xuống LOW khi phát hiện thẻ trong vùng
// → ESP32 nhận ngắt FALLING edge → set cờ → loop() xử lý ngay
// Lý do chọn GPIO15: hỗ trợ interrupt, không ảnh hưởng boot mode
#define RFID_IRQ_PIN 15

// ============================================================
// THỜI GIAN (ms) - dùng millis() dựa trên Hardware Timer0 ESP32
// millis() được Arduino Core cấu hình qua esp_timer (hardware timer
// nội bộ của ESP32), không phải phần mềm - Tham chiếu Chương 2 Timer
// ============================================================
const unsigned long UNLOCK_DURATION      = 3000;  // Relay bật 3 giây rồi tự tắt
const unsigned long UNLOCK_COOLDOWN      = 5000;  // Chống mở liên tục < 5 giây
const unsigned long CARD_DEBOUNCE_TIME   = 1000;  // Chống đọc thẻ trùng trong 1 giây
const unsigned long FINGERPRINT_INTERVAL = 2000;  // Polling vân tay mỗi 2 giây
const unsigned long BRUTE_FORCE_LOCKOUT  = 30000; // Khoá hệ thống 30 giây khi bị tấn công
const int           FAIL_THRESHOLD       = 3;     // Số lần thất bại trước khi ALARM
const int           WDT_TIMEOUT          = 60;    // [MỚI] WDT timeout 60 giây (Chương 3)

// --- NVS namespace ---
const char* NVS_NAMESPACE = "smartlock";  // Partition name trong NVS Flash

// ============================================================
// MQTT TOPICS
// ============================================================
const char* TOPIC_ACCESS_LOG         = "smartlock/access/log";
const char* TOPIC_ENROLL_RFID_RESULT = "smartlock/enroll/rfid";
const char* TOPIC_ENROLL_FP_RESULT   = "smartlock/enroll/fingerprint/result";
const char* TOPIC_DELETE_FP_RESULT   = "smartlock/delete/fingerprint/result";
const char* TOPIC_STATUS             = "smartlock/status";

// ============================================================
// GLOBAL OBJECTS
// ============================================================
WiFiClientSecure     espClient;              // WiFi client có hỗ trợ TLS
PubSubClient         mqttClient(espClient);  // MQTT client publish/subscribe
HardwareSerial       fingerSerial(1);        // UART1 dành riêng cho AS608
                                             // Lý do dùng HardwareSerial(1):
                                             // UART1 có FIFO buffer 128 bytes
                                             // phần cứng, tránh mất dữ liệu
                                             // khi AS608 gửi response nhanh
Adafruit_Fingerprint finger(&fingerSerial);  // Đối tượng AS608 (Character Driver)
MFRC522              rfid(SS_PIN, RST_PIN);  // Đối tượng MFRC522 (Character Driver)
Preferences          prefs;                  // Đối tượng NVS Flash storage

// ============================================================
// STATE MACHINE 
// ============================================================
enum LockState { LOCKED, UNLOCKING, ALARM };
LockState lockState = LOCKED;  // Mặc định: khoá đóng (trạng thái Idle)

unsigned long unlockStartTime = 0;  // Thời điểm bắt đầu UNLOCKING (để auto-close)
unsigned long lastUnlockTime  = 0;  // Thời điểm mở lần cuối (cho cooldown)

// ============================================================
// DRIVER STATE MACHINE
// Mỗi driver phải quản lý trạng thái Idle/Busy/Finish
// và có cơ chế Acquire (khóa độc quyền) / Release (giải phóng)
// ============================================================
enum DriverState { DRV_IDLE, DRV_BUSY, DRV_FINISH };

// Trạng thái driver RFID
DriverState rfidDriverState = DRV_IDLE;

// Trạng thái driver Fingerprint
DriverState fpDriverState   = DRV_IDLE;

// Acquire driver: ngăn 2 tác vụ dùng cùng 1 driver đồng thời
// Trả về true nếu acquire thành công, false nếu driver đang bận
bool acquireRFIDDriver() {
  if (rfidDriverState != DRV_IDLE) {
    Serial.println("⚠️ RFID Driver đang BUSY - Từ chối acquire");
    return false;
  }
  rfidDriverState = DRV_BUSY;
  Serial.println("[RFID Driver] → BUSY");
  return true;
}

void releaseRFIDDriver() {
  rfidDriverState = DRV_IDLE;
  Serial.println("[RFID Driver] → IDLE");
}

bool acquireFingerprintDriver() {
  if (fpDriverState != DRV_IDLE) {
    Serial.println("⚠️ Fingerprint Driver đang BUSY - Từ chối acquire");
    return false;
  }
  fpDriverState = DRV_BUSY;
  Serial.println("[FP Driver] → BUSY");
  return true;
}

void releaseFingerprintDriver() {
  fpDriverState = DRV_IDLE;
  Serial.println("[FP Driver] → IDLE");
}

// ============================================================
// BRUTE-FORCE PROTECTION
// ============================================================
int  failCount            = 0;      // Số lần thất bại liên tiếp
bool bruteForceActive     = false;  // Đang bị lockout không
unsigned long bruteForceStartTime = 0;

// ============================================================
// ENROLLMENT STATE
// ============================================================
bool   enrollingRFID          = false;
String enrollingRFIDUserId    = "";

bool   enrollingFingerprint       = false;
String enrollingFingerprintUserId = "";
int    enrollingFingerprintId     = -1;

// ============================================================
// RFID DEBOUNCE
// ============================================================
String        lastCardUID  = "";
unsigned long lastCardTime = 0;

// ============================================================
// INTERRUPT SERVICE ROUTINE (ISR) cho RFID
// ============================================================
// Biến volatile: báo cho compiler biết biến này có thể thay đổi
// bất kỳ lúc nào (từ ISR) - không được tối ưu hoá bộ nhớ cache
// Đây là yêu cầu bắt buộc khi dùng biến trong ISR 
volatile bool rfidCardDetected = false;

// IRAM_ATTR: đặt ISR vào Internal RAM thay vì Flash để thực thi nhanh
// ISR phải cực ngắn: chỉ set cờ, KHÔNG làm việc nặng như Serial.print
// Đây là "vùng tới hạn" (Critical Section) 
void IRAM_ATTR rfidIRQHandler() {
  rfidCardDetected = true;  // Chỉ set cờ, loop() sẽ xử lý
}

// ============================================================
// SECTION 1: NVS - QUẢN LÝ UID HỢP LỆ
// ============================================================
// Lưu danh sách UID thẻ RFID vào NVS Flash (tương đương EEPROM)
// Key: "uid_XXXX" → Value: userId
// Dữ liệu tồn tại qua reset và mất điện

void nvsBegin() {
  prefs.begin(NVS_NAMESPACE, false);  // false = read-write mode
  Serial.println("  [NVS] Namespace: " + String(NVS_NAMESPACE));
}

bool isUIDValid(String uid) {
  String key = "uid_" + uid;
  return prefs.getString(key.c_str(), "").length() > 0;
}

String getUserIdByUID(String uid) {
  String key = "uid_" + uid;
  return prefs.getString(key.c_str(), "");
}

bool saveUID(String uid, String userId) {
  String key = "uid_" + uid;
  bool ok = prefs.putString(key.c_str(), userId.c_str());
  Serial.println(ok ? "✓ UID đã lưu NVS" : "✗ Lưu UID thất bại");
  return ok;
}

bool deleteUID(String uid) {
  String key = "uid_" + uid;
  bool ok = prefs.remove(key.c_str());
  Serial.println(ok ? "✓ UID đã xoá NVS" : "✗ Xoá UID thất bại");
  return ok;
}

void clearAllUIDs() {
  prefs.clear();
  Serial.println("✓ Đã xoá toàn bộ UID trong NVS");
}

// ============================================================
// SECTION 2: BRUTE-FORCE PROTECTION
// ============================================================

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

    String alert = "{\"device_id\":\"" + device_id + "\","
                   "\"event\":\"brute_force_detected\","
                   "\"method\":\"" + method + "\","
                   "\"fail_count\":" + String(failCount) + ","
                   "\"timestamp\":" + String(millis()) + "}";
    mqttClient.publish(TOPIC_ACCESS_LOG, alert.c_str());
  }
}

void resetFailCount() { failCount = 0; }

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

// ============================================================
// SECTION 3: HARDWARE CONTROL
// ============================================================

void publishAccessLog(String method, bool success,
                      String userId, String reason);

void openLock(String method, String userId) {
  if (lockState == UNLOCKING) {
    Serial.println("⚠️ Đang mở khoá - Bỏ qua");
    return;
  }
  if (millis() - lastUnlockTime < UNLOCK_COOLDOWN) {
    Serial.println("⚠️ Cooldown - Chờ thêm");
    return;
  }

  Serial.println("🔓 MỞ KHOÁ | method: " + method + " | user: " + userId);
  lockState       = UNLOCKING;    // → trạng thái Busy
  unlockStartTime = millis();
  lastUnlockTime  = millis();
  digitalWrite(RELAY_PIN, HIGH);  // Bật relay → mở khoá điện từ

  resetFailCount();
  publishAccessLog(method, true, userId, "");
  mqttClient.publish(TOPIC_STATUS, "{\"status\":\"unlocked\"}");
}

void closeLock() {
  lockState = LOCKED;             // → trạng thái Idle
  digitalWrite(RELAY_PIN, LOW);
  Serial.println("🔒 KHOÁ CỬA");

  // Reset debounce RFID
  lastCardUID  = "";
  lastCardTime = 0;

  //  Reset cờ và kích hoạt lại IRQ sau khi khoá lại
  rfidCardDetected = false;

  delay(50);
  rfid.PCD_Init();
  delay(50);

  if (mqttClient.connected()) {
    mqttClient.publish(TOPIC_STATUS, "{\"status\":\"locked\"}");
    mqttClient.loop();
  }
}

void denyAccess(String method, String reason) {
  Serial.println("✗ TỪ CHỐI | " + method + " | " + reason);
  recordFailedAttempt(method);
  publishAccessLog(method, false, "", reason);
}

// ============================================================
// SECTION 4: PUBLISH HELPERS
// ============================================================

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

// ============================================================
// SECTION 5: RFID - CHARACTER DRIVER 
// ============================================================
// RFID là Character Driver: truyền từng byte UID, không cần buffer lớn
// Giao tiếp SPI 4MHz: SCK=18, MISO=19, MOSI=23, SS=2, RST=4
// Lý do chọn SPI: tốc độ cao, full duplex 

// Autoconfiguration: kiểm tra version chip
// khi khởi động để xác nhận driver phát hiện đúng thiết bị
bool rfidAutoconfig() {
  byte version = rfid.PCD_ReadRegister(MFRC522::VersionReg);
  Serial.printf("  [RFID Autoconfig] Version Register: 0x%02X\n", version);
  if (version == 0x91) {
    Serial.println("  [RFID Autoconfig] ✓ MFRC522 v1.0 detected");
    return true;
  } else if (version == 0x92) {
    Serial.println("  [RFID Autoconfig] ✓ MFRC522 v2.0 detected");
    return true;
  } else if (version == 0x00 || version == 0xFF) {
    Serial.println("  [RFID Autoconfig] ✗ Module không phản hồi!");
    return false;
  } else {
    Serial.printf("  [RFID Autoconfig] ⚠️ Version lạ: 0x%02X (vẫn tiếp tục)\n", version);
    return true;
  }
}

//  Kích hoạt chế độ ngắt IRQ cho MFRC522
// Dùng DivIEnReg (ngắt phát hiện thẻ) thay vì ComIEnReg (ngắt Rx)
// để tránh false interrupt liên tục khi không có thẻ trong vùng
void rfidEnableIRQ() {
  // DivIEnReg bit 4 (MFinActIEn): kích hoạt ngắt khi thẻ vào vùng RF
  // bit 7 = 1: IRQ pin active LOW (kéo chân xuống 0V khi có sự kiện)
  rfid.PCD_WriteRegister(MFRC522::DivIEnReg,  0x90);
  // Xoá cờ ngắt cũ trong chip trước khi enable (tránh kích ngay lập tức)
  rfid.PCD_WriteRegister(MFRC522::DivIrqReg,  0x04);
  rfidCardDetected = false;  // Reset cờ phần mềm
}

void handleRFIDCard(String uid) {
  Serial.println("\n=== XỬ LÝ RFID ===");
  Serial.println("UID: " + uid);

  if (isBruteForceLocked()) {
    unsigned long rem = BRUTE_FORCE_LOCKOUT - (millis() - bruteForceStartTime);
    Serial.printf("🚫 Brute-force lockout còn %.1fs\n", rem / 1000.0);
    return;
  }

  if (isUIDValid(uid)) {
    String userId = getUserIdByUID(uid);
    Serial.println("✓ UID hợp lệ - User: " + userId);
    openLock("rfid", userId);
  } else {
    Serial.println("✗ UID không tồn tại");
    denyAccess("rfid", "uid_not_found");
  }
}

void handleEnrollRFIDCard(String uid) {
  // Kiểm tra driver RFID có đang bận không
  // Nếu đang đăng ký thẻ mà có thẻ khác, vẫn xử lý bình thường
  Serial.println("💳 ENROLL RFID: " + uid + " | User: " + enrollingRFIDUserId);

  if (isUIDValid(uid)) {
    String msg = "{\"status\":\"failed\",\"uid\":\"" + uid +
                 "\",\"userId\":\"" + enrollingRFIDUserId +
                 "\",\"device_id\":\"" + device_id +
                 "\",\"reason\":\"uid_already_exists\"}";
    mqttClient.publish(TOPIC_ENROLL_RFID_RESULT, msg.c_str());
    Serial.println("✗ UID đã tồn tại!");
  } else {
    saveUID(uid, enrollingRFIDUserId);
    String msg = "{\"status\":\"success\",\"uid\":\"" + uid +
                 "\",\"userId\":\"" + enrollingRFIDUserId +
                 "\",\"device_id\":\"" + device_id + "\"}";
    mqttClient.publish(TOPIC_ENROLL_RFID_RESULT, msg.c_str());
    Serial.println("✓ Enroll RFID thành công");
  }

  enrollingRFID       = false;
  enrollingRFIDUserId = "";
  // Driver sẽ được release tự động ở cuối khối IRQ trong loop()
}

// ============================================================
// SECTION 6: FINGERPRINT - CHARACTER DRIVER 
// ============================================================
// AS608 là Character Driver: giao tiếp UART 57600 baud, 8N1
// Lý do chọn UART: point-to-point đơn giản, dễ debug 
// AS608 tự xử lý so khớp nội bộ (hardware decision) - phân hoạch cứng/mềm

// Autoconfiguration: xác nhận AS608 hoạt động
bool fingerprintAutoconfig() {
  Serial.println("  [FP Autoconfig] Kiểm tra AS608...");
  if (finger.verifyPassword()) {
    // Lấy thêm thông tin từ chip
    Serial.printf("  [FP Autoconfig] ✓ AS608 online\n");
    Serial.printf("  [FP Autoconfig]   Template count : %d / 162\n",
                  finger.templateCount);
    Serial.printf("  [FP Autoconfig]   Status register: 0x%04X\n",
                  finger.status_reg);
    Serial.printf("  [FP Autoconfig]   System ID      : 0x%04X\n",
                  finger.system_id);
    Serial.printf("  [FP Autoconfig]   Capacity       : %d slots\n",
                  finger.capacity);
    return true;
  } else {
    Serial.println("  [FP Autoconfig] ✗ Không tìm thấy AS608!");
    Serial.println("  [FP Autoconfig]   Kiểm tra dây TX/RX và nguồn 5V");
    return false;
  }
}

int getFingerprintID() {
  uint8_t p = finger.getImage();
  if (p == FINGERPRINT_NOFINGER) return -1;
  if (p != FINGERPRINT_OK)       return -1;

  p = finger.image2Tz();
  if (p != FINGERPRINT_OK) return -1;

  p = finger.fingerFastSearch();
  if (p == FINGERPRINT_OK)       return finger.fingerID;
  if (p == FINGERPRINT_NOTFOUND) return -2;
  return -1;
}

void handleFingerprintMatch(int fpId) {
  Serial.println("\n=== XỬ LÝ VÂN TAY ===");

  if (isBruteForceLocked()) {
    unsigned long rem = BRUTE_FORCE_LOCKOUT - (millis() - bruteForceStartTime);
    Serial.printf("🚫 Brute-force lockout còn %.1fs\n", rem / 1000.0);
    return;
  }

  if (fpId >= 0) {
    Serial.println("✓ VÂN TAY HỢP LỆ - ID: " + String(fpId));
    openLock("fingerprint", String(fpId));
  } else {
    Serial.println("✗ Vân tay không hợp lệ");
    denyAccess("fingerprint", "fingerprint_not_found");
  }
}

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

// enrollFingerprintRemote với:
// 1. Acquire/Release driver để tránh xung đột
// 2. Kiểm tra UART buffer overflow (Stream Driver FIFO)
// 3. WDT reset trong vòng lặp blocking để tránh treo hệ thống
void enrollFingerprintRemote(uint8_t id, String userId) {
  // Kiểm tra fingerprint driver có bận không
  if (!acquireFingerprintDriver()) {
    Serial.println("✗ Fingerprint driver bận - Huỷ enroll");
    sendFingerprintEnrollResult(false, id, userId, "driver_busy");
    return;
  }

  Serial.println("=== ĐĂNG KÝ VÂN TAY | ID: " + String(id) + " ===");
  uint8_t p = -1;
  unsigned long t;

  // Helper: dọn dẹp và báo lỗi khi thất bại
  auto failReturn = [&](String reason) {
    sendFingerprintEnrollResult(false, id, userId, reason);
    enrollingFingerprint = false;
    releaseFingerprintDriver();  // Release driver
    rfid.PCD_Init();
    rfidEnableIRQ();             // Kích hoạt lại ngắt RFID
    delay(50);
  };

  // [Stream Driver FIFO] Xả buffer UART trước khi bắt đầu
  // Tránh dữ liệu cũ còn trong FIFO làm nhiễu quá trình đăng ký
  while (fingerSerial.available()) {
    fingerSerial.read();
  }
  Serial.println("  [FP FIFO] Buffer cleared");

  // --- Scan lần 1 ---
  Serial.println("Đặt ngón tay lên cảm biến...");
  t = millis();
  while (p != FINGERPRINT_OK) {
    esp_task_wdt_reset();  //  Vỗ WDT trong vòng lặp blocking
    if (millis() - t > 15000) { failReturn("timeout_scan1"); return; }

    // [Stream Driver] Kiểm tra buffer overflow UART
    if (fingerSerial.available() > 100) {
      Serial.println("⚠️ UART buffer overflow - Xả buffer");
      while (fingerSerial.available()) fingerSerial.read();
    }

    p = finger.getImage();
    if (p == FINGERPRINT_NOFINGER) { delay(100); continue; }
    if (p != FINGERPRINT_OK)       { failReturn("image_error_scan1"); return; }
  }
  if (finger.image2Tz(1) != FINGERPRINT_OK) { failReturn("convert_error_scan1"); return; }

  // --- Nhấc ngón tay ---
  Serial.println("Nhấc ngón tay ra...");
  unsigned long waitStart = millis();
  while (finger.getImage() != FINGERPRINT_NOFINGER) {
    esp_task_wdt_reset();  // Vỗ WDT
    if (millis() - waitStart > 10000) { failReturn("timeout_lift_finger"); return; }
    delay(100);
  }
  delay(500);

  // --- Scan lần 2 ---
  Serial.println("Đặt lại ngón tay...");
  p = -1; t = millis();
  while (p != FINGERPRINT_OK) {
    esp_task_wdt_reset();  //  Vỗ WDT
    if (millis() - t > 15000) { failReturn("timeout_scan2"); return; }

    // [Stream Driver] Kiểm tra buffer overflow lần 2
    if (fingerSerial.available() > 100) {
      Serial.println("⚠️ UART buffer overflow - Xả buffer");
      while (fingerSerial.available()) fingerSerial.read();
    }

    p = finger.getImage();
    if (p == FINGERPRINT_NOFINGER) { delay(100); continue; }
    if (p != FINGERPRINT_OK)       { failReturn("image_error_scan2"); return; }
  }
  if (finger.image2Tz(2) != FINGERPRINT_OK) { failReturn("convert_error_scan2"); return; }

  // --- Tạo model ---
  p = finger.createModel();
  if (p == FINGERPRINT_ENROLLMISMATCH) { failReturn("fingerprint_mismatch"); return; }
  if (p != FINGERPRINT_OK)             { failReturn("model_error"); return; }

  // --- Lưu vào AS608 ---
  p = finger.storeModel(id);
  if (p == FINGERPRINT_OK) {
    Serial.println("✓ Vân tay lưu thành công - ID: " + String(id));
    sendFingerprintEnrollResult(true, id, userId, "");
  } else {
    sendFingerprintEnrollResult(false, id, userId, "store_error");
  }

  // Reinit RFID và bật lại ngắt
  rfid.PCD_Init();
  rfidEnableIRQ();             //  Kích hoạt lại ngắt RFID sau blocking dài
  delay(50);
  enrollingFingerprint = false;
  releaseFingerprintDriver();  // Release fingerprint driver
}

void clearAllFingerprints() {
  uint8_t p = finger.emptyDatabase();
  Serial.println(p == FINGERPRINT_OK
      ? "✓ Đã xóa toàn bộ vân tay AS608"
      : "✗ Xóa vân tay thất bại: " + String(p));
}

void deleteFingerprintRemote(uint8_t id, String userId) {
  Serial.println("🗑️ XOÁ VÂN TAY ID: " + String(id));
  uint8_t p = finger.deleteModel(id);

  String msg = "{\"status\":\"" + String(p == FINGERPRINT_OK ? "success" : "failed") +
               "\",\"fingerprintId\":" + String(id) +
               ",\"userId\":\"" + userId +
               "\",\"device_id\":\"" + device_id + "\"";
  if (p != FINGERPRINT_OK)
    msg += ",\"reason\":\"delete_error_" + String(p) + "\"";
  msg += "}";
  mqttClient.publish(TOPIC_DELETE_FP_RESULT, msg.c_str());
  Serial.println(p == FINGERPRINT_OK ? "✓ Xoá thành công" : "✗ Xoá thất bại");
}

// ============================================================
// SECTION 7: MQTT CALLBACK
// ============================================================

void mqttCallback(char* topic, byte* payload, unsigned int length) {
  String topicStr = String(topic);
  String message  = "";
  for (unsigned int i = 0; i < length; i++) message += (char)payload[i];

  Serial.println("\n📨 MQTT: " + topicStr);
  Serial.println("   " + message);

  // --- Lệnh mở khoá từ app (khuôn mặt) ---
  if (topicStr == "smartlock/device/" + device_id + "/control/unlock") {
    Serial.println("📱 Lệnh mở khoá từ app");
    String userId = "";
    int uS = message.indexOf("\"user_id\":\"") + 11;
    int uE = message.indexOf("\"", uS);
    if (uS > 10 && uE > uS) userId = message.substring(uS, uE);

    if (lockState != UNLOCKING) openLock("face", userId);

    if (userId.length() > 0) {
      String confirm = "{\"device_id\":\"" + device_id +
                       "\",\"status\":\"valid\",\"user_id\":\"" + userId +
                       "\",\"timestamp\":" + String(millis()) + "}";
      mqttClient.publish("smartlock/sensor/face/unlock", confirm.c_str());
    }
    return;
  }

  // --- Lệnh đăng ký RFID ---
  if (topicStr == "smartlock/device/" + device_id + "/enroll/rfid") {
    if (message.startsWith("ENROLL_RFID:")) {
      // Enroll RFID chỉ cần set cờ enrollingRFID = true rồi chờ người quẹt thẻ.
      // KHÔNG acquire driver ở đây vì driver chỉ nên BUSY khi đang đọc thẻ thực sự,
      // không phải khi đang chờ người dùng mang thẻ lại.
      // Driver sẽ tự BUSY trong loop() khi thẻ được detect qua IRQ/polling.
      enrollingRFIDUserId = message.substring(12);
      enrollingRFID       = true;
      Serial.println("✓ Chế độ enroll RFID - Chờ quẹt thẻ | User: " + enrollingRFIDUserId);
    }
    return;
  }

  // --- Lệnh xoá RFID ---
  if (topicStr == "smartlock/device/" + device_id + "/delete/rfid") {
    int uS = message.indexOf("\"uid\":\"") + 7;
    int uE = message.indexOf("\"", uS);
    if (uS > 6 && uE > uS) {
      String uid = message.substring(uS, uE);
      deleteUID(uid);
    }
    return;
  }

  // --- Lệnh xoá toàn bộ device ---
  if (topicStr == "smartlock/device/" + device_id + "/clear") {
    Serial.println("🗑️ Nhận lệnh xoá device - Xoá NVS + AS608");
    clearAllUIDs();
    clearAllFingerprints();
    return;
  }

  // --- Lệnh đăng ký vân tay ---
  if (topicStr == "smartlock/device/" + device_id + "/enroll/fingerprint") {
    if (message.startsWith("ENROLL_FINGERPRINT:")) {
      int c1 = message.indexOf(':');
      int c2 = message.indexOf(':', c1 + 1);
      enrollingFingerprintUserId = message.substring(c1 + 1, c2);
      enrollingFingerprintId     = message.substring(c2 + 1).toInt();
      enrollingFingerprint       = true;
      Serial.println("✓ Enroll vân tay | ID: " + String(enrollingFingerprintId));
      enrollFingerprintRemote(enrollingFingerprintId, enrollingFingerprintUserId);
    }
    return;
  }

  // --- Lệnh xoá vân tay ---
  if (topicStr == "smartlock/device/" + device_id + "/delete/fingerprint") {
    if (message.startsWith("DELETE_FINGERPRINT:")) {
      int c1 = message.indexOf(':');
      int c2 = message.indexOf(':', c1 + 1);
      String userId = message.substring(c1 + 1, c2);
      int    fpId   = message.substring(c2 + 1).toInt();
      deleteFingerprintRemote(fpId, userId);
    }
    return;
  }
}

// ============================================================
// SECTION 8: MQTT CONNECT
// ============================================================

void subscribeTopics() {
  String base = "smartlock/device/" + device_id + "/";
  mqttClient.subscribe((base + "control/unlock").c_str());
  mqttClient.subscribe((base + "enroll/rfid").c_str());
  mqttClient.subscribe((base + "delete/rfid").c_str());
  mqttClient.subscribe((base + "enroll/fingerprint").c_str());
  mqttClient.subscribe((base + "delete/fingerprint").c_str());
  mqttClient.subscribe((base + "clear").c_str());
  Serial.println("✓ Subscribed tất cả topics");
}

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
      esp_task_wdt_reset();  // [MỚI] Vỗ WDT trong khi chờ MQTT
      delay(5000);
    }
  }
}

// ============================================================
// SECTION 9: WIFI
// ============================================================

void setupWiFi() {
  Serial.println("Kết nối WiFi: " + String(ssid));
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  int attempt = 0;
  while (WiFi.status() != WL_CONNECTED && attempt < 40) {
    esp_task_wdt_reset();  //  Vỗ WDT trong khi chờ WiFi
    delay(500);
    Serial.print(".");
    attempt++;
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    Serial.println("✓ WiFi kết nối thành công");
    Serial.println("  IP  : " + WiFi.localIP().toString());
    Serial.println("  RSSI: " + String(WiFi.RSSI()) + " dBm");
    Serial.println("  MAC : " + WiFi.macAddress());
  } else {
    Serial.println("✗ WiFi thất bại - Chạy OFFLINE (RFID/vân tay vẫn hoạt động)");
  }
}

// ============================================================
// SECTION 10: SETUP
// ============================================================

void setup() {
  // --- Relay: khởi tạo ở LOW (khoá đóng) - an toàn khi khởi động ---
  // Lý do khởi tạo LOW trước Serial: tránh relay bật trong khoảnh khắc
  // GPIO chưa được init đúng khi ESP32 mới khởi động
  pinMode(RELAY_PIN, OUTPUT);
  digitalWrite(RELAY_PIN, LOW);

  Serial.begin(57600);
  delay(100);
  Serial.println("\n========== SMART LOCK BOOT ==========");
  Serial.println("Firmware: v2.0 (improved)");
  Serial.println("Device ID: " + device_id);

  // -------------------------------------------------------
  // Khởi tạo Watchdog Timer
  // WDT_TIMEOUT = 60 giây: nếu loop() không gọi
  // esp_task_wdt_reset() trong 60s → tự động reset ESP32
  // Bảo vệ khỏi: treo màn hình WiFi, blocking UART vô hạn,
  // vòng lặp vô tận trong enrollFingerprintRemote()
  // -------------------------------------------------------
  // IDF v5.x (ESP32 Arduino Core v3.x) dùng struct config thay vì 2 tham số rời
  // Tham chiếu: esp_task_wdt.h - esp_task_wdt_init(const esp_task_wdt_config_t*)
  const esp_task_wdt_config_t wdt_config = {
    .timeout_ms    = (uint32_t)(WDT_TIMEOUT * 1000), // Đơn vị ms trong IDF v5
    .idle_core_mask = 0,                              // Không giám sát idle task
    .trigger_panic  = true                            // Gây panic/reset khi timeout
  };
  esp_task_wdt_init(&wdt_config);
  esp_task_wdt_add(NULL);                // Thêm task hiện tại (main loop)
  Serial.println("✓ Watchdog Timer khởi tạo (" +
                 String(WDT_TIMEOUT) + "s timeout)");

  // --- NVS Flash ---
  nvsBegin();
  Serial.println("✓ NVS Flash khởi tạo");

  // --- WiFi ---
  setupWiFi();

  // --- MQTT (chỉ khi có WiFi) ---
  if (WiFi.status() == WL_CONNECTED) {
    espClient.setInsecure();         // Bỏ qua verify SSL cert (dùng cho dev)
    mqttClient.setBufferSize(2048);  // Buffer 2KB: đủ cho payload JSON lớn nhất
                                     // Lý do 2048: payload enroll có thể ~512B
                                     // + overhead MQTT header ~50B
    mqttClient.setServer(mqtt_server, mqtt_port);
    mqttClient.setCallback(mqttCallback);
    mqttClient.setKeepAlive(60);
  }

  // -------------------------------------------------------
  // FINGERPRINT Autoconfiguration
  // Driver tự phát hiện và log thông tin thiết bị khi khởi động
  // -------------------------------------------------------
  Serial.println("\n--- Fingerprint Driver Autoconfiguration ---");
  fingerSerial.begin(57600, SERIAL_8N1, FINGER_RX, FINGER_TX);
  // Lý do 57600 baud: tốc độ mặc định AS608, cân bằng tốc độ/ổn định
  // SERIAL_8N1: 8 data bits, No parity, 1 stop bit - chuẩn UART cơ bản
  finger.begin(57600);
  delay(500);
  fingerprintAutoconfig();  // Autoconfiguration

  // -------------------------------------------------------
  // RFID Autoconfiguration
  // Driver tự phát hiện và log thông tin chip khi khởi động
  // -------------------------------------------------------
  Serial.println("\n--- RFID Driver Autoconfiguration ---");
  SPI.begin(18, 19, 23, SS_PIN);
  // Lý do các chân SPI:
  //   SCK=18: SPI clock mặc định ESP32 VSPI
  //   MISO=19: MFRC522 → ESP32 (nhận data)
  //   MOSI=23: ESP32 → MFRC522 (gửi data)
  //   SS=2: chọn chip MFRC522 (LOW = active)
  rfid.PCD_Init();
  rfidAutoconfig();  //  Autoconfiguration

  // -------------------------------------------------------
  //  Cài đặt External Interrupt cho RFID IRQ
  // Ngắt ngoài FALLING: kích hoạt khi IRQ pin từ HIGH → LOW
  // (MFRC522 kéo IRQ xuống LOW khi phát hiện thẻ trong vùng)
  // Tham chiếu: (ngắt ngoài INT0/INT1)
  // -------------------------------------------------------
  Serial.println("\n--- RFID External Interrupt Setup ---");
  pinMode(RFID_IRQ_PIN, INPUT_PULLUP);
  // INPUT_PULLUP: điện trở kéo lên nội bộ, đảm bảo mức HIGH khi không có thẻ
  attachInterrupt(
    digitalPinToInterrupt(RFID_IRQ_PIN),  // Chuyển GPIO → interrupt number
    rfidIRQHandler,                        // Con trỏ tới ISR (IRAM_ATTR)
    FALLING                                // Kích hoạt khi cạnh xuống (HIGH→LOW)
  );
  rfidEnableIRQ();  // Cấu hình MFRC522 phát tín hiệu IRQ
  Serial.println("✓ RFID Interrupt đã đăng ký (GPIO" +
                 String(RFID_IRQ_PIN) + " FALLING edge)");
  Serial.println("  ISR: rfidIRQHandler() [IRAM_ATTR]");
  Serial.println("  Flag: volatile bool rfidCardDetected");

  Serial.println("\n========== BOOT HOÀN TẤT ==========");
  Serial.println("Sẵn sàng xác thực:");
  Serial.println("  - RFID  : Interrupt-driven (GPIO" +
                 String(RFID_IRQ_PIN) + ")");
  Serial.println("  - Vân tay: Polling mỗi " +
                 String(FINGERPRINT_INTERVAL) + "ms");
  Serial.println("  - Khuôn mặt: Qua MQTT lệnh control/unlock");
  Serial.println("  - WDT   : " + String(WDT_TIMEOUT) + "s timeout");
  Serial.println("=====================================\n");
}

// ============================================================
// SECTION 11: MAIN LOOP 
// ============================================================
// Kiến trúc: bare-metal cooperative scheduling
// Thứ tự ưu tiên (từ cao → thấp):
//   1. WDT reset (giữ hệ thống sống)
//   2. MQTT keepalive
//   3. Auto-close relay (thời gian thực)
//   4. Brute-force check
//   5. Xử lý RFID từ interrupt flag
//   6. Polling vân tay
// ============================================================

void loop() {
  // 1.  Vỗ WDT mỗi chu kỳ loop để báo hệ thống còn sống
  // Tham chiếu: (Watchdog Timer)
  esp_task_wdt_reset();

  // 2. Duy trì kết nối MQTT
  if (WiFi.status() == WL_CONNECTED) {
    if (!mqttClient.connected()) mqttReconnect();
    mqttClient.loop();
  }

  // 3. Tự động khoá lại sau UNLOCK_DURATION
  if (lockState == UNLOCKING) {
    if (millis() - unlockStartTime >= UNLOCK_DURATION) {
      closeLock();
    }
    return;
  }

  // 4. Không xử lý cảm biến khi đang bị khoá brute-force
  if (isBruteForceLocked()) return;

  // -------------------------------------------------------
  // 5.  Xử lý RFID từ Interrupt Flag
  //
  // Luồng hoạt động:
  //   [ISR - IRAM]  rfidIRQHandler() ← FALLING edge trên GPIO15
  //       ↓ set cờ volatile
  //   [loop()]      kiểm tra rfidCardDetected
  //       ↓ nếu true → đọc UID qua SPI → xử lý
  // -------------------------------------------------------
  if (rfidDriverState == DRV_IDLE && rfidCardDetected) {
    rfidCardDetected = false;  // Reset cờ ngay (tránh xử lý 2 lần)

    // Delay nhỏ để RF field ổn định sau khi IRQ kích
    // (tránh đọc SPI khi thẻ vẫn đang vào vùng)
    delay(10);

    // Kiểm tra module RFID có thực sự có thẻ không (lọc false IRQ)
    if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {

      // Acquire driver: đánh dấu RFID đang bận trong khi xử lý thẻ
      acquireRFIDDriver();

      // Đọc UID từ SPI
      String uid = "";
      for (byte i = 0; i < rfid.uid.size; i++) {
        if (rfid.uid.uidByte[i] < 0x10) uid += "0";
        uid += String(rfid.uid.uidByte[i], HEX);
      }
      uid.toUpperCase();

      rfid.PICC_HaltA();
      rfid.PCD_StopCrypto1();

      // Debounce: bỏ qua nếu cùng thẻ trong vòng CARD_DEBOUNCE_TIME
      if (uid == lastCardUID &&
          (millis() - lastCardTime) < CARD_DEBOUNCE_TIME) {
        Serial.println("[RFID IRQ] Debounce - bỏ qua thẻ trùng");
      } else {
        lastCardUID  = uid;
        lastCardTime = millis();
        Serial.println("[RFID IRQ] Thẻ phát hiện qua ngắt: " + uid);

        // Điều hướng xử lý
        if (enrollingRFID) {
          handleEnrollRFIDCard(uid);
        } else {
          handleRFIDCard(uid);
        }
      }

      // Release driver sau khi xử lý thẻ xong
      releaseRFIDDriver();

    } else {
      // IRQ kích nhưng không có thẻ thực: nhiễu RF, bỏ qua
      // Không log liên tục ở đây để tránh spam Serial
    }

    // Kích hoạt lại ngắt sau khi xử lý xong
    rfidEnableIRQ();

    // Drain MQTT
    for (int i = 0; i < 5; i++) {
      mqttClient.loop();
      delay(10);
    }
  }

  // -------------------------------------------------------
  // Fallback polling RFID (backup khi IRQ không kích hoạt)
  // Dùng cơ chế polling 300ms làm dự phòng để đảm bảo
  // không bỏ sót thẻ trong trường hợp IRQ bị miss
  // -------------------------------------------------------
  static unsigned long lastRFIDCheck = 0;
  if (rfidDriverState == DRV_IDLE &&
      !rfidCardDetected &&
      (millis() - lastRFIDCheck >= 300)) {
    lastRFIDCheck = millis();

    // Kiểm tra health của RFID module
    byte v = rfid.PCD_ReadRegister(MFRC522::VersionReg);
    if (v == 0x00 || v == 0xFF) {
      Serial.println("⚠️ RFID không phản hồi - Reinit...");
      rfid.PCD_Init();
      rfidEnableIRQ();
      delay(50);
      return;
    }

    // Polling backup: kiểm tra có thẻ không
    if (rfid.PICC_IsNewCardPresent() && rfid.PICC_ReadCardSerial()) {
      String uid = "";
      for (byte i = 0; i < rfid.uid.size; i++) {
        if (rfid.uid.uidByte[i] < 0x10) uid += "0";
        uid += String(rfid.uid.uidByte[i], HEX);
      }
      uid.toUpperCase();

      rfid.PICC_HaltA();
      rfid.PCD_StopCrypto1();

      if (!(uid == lastCardUID &&
            (millis() - lastCardTime) < CARD_DEBOUNCE_TIME)) {
        lastCardUID  = uid;
        lastCardTime = millis();
        Serial.println("[RFID Polling-Backup] Thẻ: " + uid);

        if (enrollingRFID) handleEnrollRFIDCard(uid);
        else               handleRFIDCard(uid);

        for (int i = 0; i < 10; i++) { mqttClient.loop(); delay(50); }
      }
    }
  }

  // -------------------------------------------------------
  // 6. Quét vân tay định kỳ mỗi FINGERPRINT_INTERVAL ms
  // Polling vì AS608 không có chân IRQ để kích ngắt
  // -------------------------------------------------------
  static unsigned long lastFPCheck = 0;
  if (fpDriverState == DRV_IDLE &&
      (millis() - lastFPCheck >= FINGERPRINT_INTERVAL)) {
    lastFPCheck = millis();
    if (!enrollingFingerprint) {
      int fpId = getFingerprintID();
      if (fpId >= 0)       handleFingerprintMatch(fpId);
      else if (fpId == -2) handleFingerprintMatch(-2);

      // Reinit RFID sau UART để tránh xung đột bus
      rfid.PCD_Init();
      rfidEnableIRQ();  // Kích hoạt lại ngắt sau UART
    }
  }
}
