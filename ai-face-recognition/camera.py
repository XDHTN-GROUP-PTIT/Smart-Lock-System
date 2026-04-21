import cv2
import insightface
import numpy as np
import os
import random
import time
import threading

class VideoStream:
    def __init__(self, src=0):
        self.stream = cv2.VideoCapture(src)
        self.stream.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        self.stream.set(cv2.CAP_PROP_FPS, 30)
        self.stream.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
        self.stream.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
        self.stopped = False
        self.frame = None
        self.lock = threading.Lock()
        
    def start(self):
        threading.Thread(target=self.update, daemon=True).start()
        return self
        
    def update(self):
        while not self.stopped:
            if self.stream.isOpened():
                ret, frame = self.stream.read()
                if ret:
                    with self.lock:
                        self.frame = frame
                    
    def read(self):
        with self.lock:
            return self.frame.copy() if self.frame is not None else None
        
    def stop(self):
        self.stopped = True
        self.stream.release()


print("Đang tải model InsightFace...")
model = insightface.app.FaceAnalysis(name='buffalo_sc', providers=['CPUExecutionProvider'])
model.prepare(ctx_id=-1)
print("Model đã sẵn sàng!")


def extract_face_embedding(image_path):
    img = cv2.imread(image_path)
    if img is None:
        print(f"Không đọc được ảnh: {image_path}")
        return None
    faces = model.get(img)
    if not faces:
        return None
    return faces[0].embedding


def cosine_similarity(emb1, emb2):
    emb1 = np.array(emb1)
    emb2 = np.array(emb2)
    return np.dot(emb1, emb2) / (np.linalg.norm(emb1) * np.linalg.norm(emb2))

known_faces_dir = "known_faces"
known_embeddings = {}

print(f"Đang tải khuôn mặt từ {known_faces_dir}...")
for filename in os.listdir(known_faces_dir):
    if filename.lower().endswith((".jpg", ".png", ".jpeg")):
        path = os.path.join(known_faces_dir, filename)
        name = os.path.splitext(filename)[0]
        emb = extract_face_embedding(path)
        if emb is not None:
            known_embeddings[name] = emb
            print(f"{name}")

print(f"\n Đã tải {len(known_embeddings)} khuôn mặt!")


def check_head_turn(video_stream, window_name="Smart Door Lock", direction="left", duration=3):
    print(f"Vui lòng quay {direction.upper()} trong {duration} giây...")

    start_time = time.time()
    initial_x = None
    moved = False

    while time.time() - start_time < duration:
        frame = video_stream.read()
        if frame is None:
            continue

        faces = model.get(frame)
        if len(faces) > 0:
            face = faces[0]
            x_center = (face.bbox[0] + face.bbox[2]) / 2

            if initial_x is None:
                initial_x = x_center

            delta = x_center - initial_x

            # Kiểm tra hướng quay
            if direction == "left" and delta > 40:
                moved = True
                break
            elif direction == "right" and delta < -40:
                moved = True
                break

        cv2.putText(frame, f"Please turn {direction.upper()}!", (20, 40),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.9, (0, 255, 255), 2)
        cv2.imshow(window_name, frame)

        if cv2.waitKey(1) & 0xFF == ord("q"):
            moved = False
            break

    return moved


print("\nKhởi động camera...")
cap = VideoStream(0).start()
time.sleep(1.0)

print("\n=== HỆ THỐNG NHẬN DIỆN KHUÔN MẶT MỞ KHÓA ===")
print("Nhấn 'q' để thoát\n")

window_name = "Smart Door Lock"
last_verify_time = 0
verify_cooldown = 5  # giây

while True:
    frame = cap.read()
    if frame is None:
        continue

    faces = model.get(frame)
    if len(faces) > 1:
        cv2.putText(frame, "Chi chi de 1 khuon mat trong khung!", (20, 40),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 0, 255), 2)
        cv2.imshow(window_name, frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break
        continue

    # Nếu không có khuôn mặt thì bỏ qua
    if len(faces) == 0:
        cv2.putText(frame, "Khong thay khuon mat...", (20, 40),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2)
        cv2.imshow(window_name, frame)
        if cv2.waitKey(1) & 0xFF == ord("q"):
            break
        continue

    for face in faces:
        emb = face.embedding
        name, max_sim = "Unknown", 0

        for known_name, known_emb in known_embeddings.items():
            sim = cosine_similarity(emb, known_emb)
            if sim > max_sim:
                max_sim = sim
                name = known_name

        x1, y1, x2, y2 = map(int, face.bbox)
        color = (0, 255, 0) if max_sim > 0.6 else (0, 0, 255)
        cv2.rectangle(frame, (x1, y1), (x2, y2), color, 2)
        cv2.putText(frame, f"{name}: {max_sim:.2f}", (x1, y1 - 10),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, color, 2)

        current_time = time.time()
        if max_sim > 0.6 and (current_time - last_verify_time) > verify_cooldown:
            print(f"\nNhận diện: {name} (similarity={max_sim:.2f})")
            last_verify_time = current_time

            action = random.choice(["left", "right"])
            ok = check_head_turn(cap, window_name=window_name, direction=action)

            if ok:
                print("MỞ KHÓA THÀNH CÔNG!")
            else:
                print("Không phát hiện đúng hành động!")
            
            time.sleep(1)

    cv2.putText(frame, "Press 'q' to quit", (10, 30),
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, (255, 255, 255), 2)
    cv2.imshow(window_name, frame)
    
    if cv2.waitKey(1) & 0xFF == ord("q"):
        break

cap.stop()
cv2.destroyAllWindows()
print("\nĐã tắt hệ thống.")
