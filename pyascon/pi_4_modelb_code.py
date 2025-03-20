import socket
import struct
import subprocess
import sys
import time  # For benchmarking
import csv  # For CSV logging
from datetime import datetime  # For timestamps
import cv2
import os
import threading

from ascon import ascon_encrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from hashlib import sha256

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
ROUTER_SSID = "Enter Router Name"
ROUTER_PASSWORD = "Enter Router Password"

LAPTOP_IP = "Enter Laptop IP"   # Replace with actual laptop IP
LAPTOP_PORT = 8888

FRAME_INTERVAL = 0.001  # Reduced delay
CAP_WIDTH = 320
CAP_HEIGHT = 240
JPEG_QUALITY = 40  # Lowered for faster transmission
CHUNK_SIZE = 512  # Optimized chunk size

# ----------------------------------------------------------------------
# Wi-Fi Connection on Ubuntu (nmcli)
# ----------------------------------------------------------------------
def connect_to_router():
    try:
        router_start_time = time.time()  # Start timing
        print(f"[INFO] Connecting to {ROUTER_SSID} via nmcli on Ubuntu...")
        subprocess.run([
            "nmcli", "d", "wifi", "connect", ROUTER_SSID,
            "password", ROUTER_PASSWORD
        ], check=True)
        router_end_time = time.time()  # End timing
        router_connection_time = router_end_time - router_start_time
        print(f"[BENCHMARK] Time to connect to router: {router_connection_time:.6f} seconds")

        # Log router connection time to CSV
        with open(log_file, mode="a", newline="") as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow([datetime.now(), "Router Connection Time", f"{router_connection_time:.6f}"])

        print(f"[INFO] Successfully connected to {ROUTER_SSID} (Ubuntu).")
    except subprocess.CalledProcessError:
        print("[ERROR] Failed to connect to Wi-Fi on Ubuntu. Exiting...")
        sys.exit(1)

# ----------------------------------------------------------------------
# Socket Helpers
# ----------------------------------------------------------------------
def send_in_chunks(sock, data, chunk_size=CHUNK_SIZE, addr=None):
    """Sends data in smaller chunks for smoother transmission."""
    for i in range(0, len(data), chunk_size):
        sock.sendto(data[i:i + chunk_size], addr)

# ----------------------------------------------------------------------
# Multi-threaded Frame Capture, Display & Sending
# ----------------------------------------------------------------------
def capture_display_and_send(s, cap, shared_key):
    # Variables for FPS calculation
    frame_count_encrypted = 0
    frame_count_unencrypted = 0
    fps_start_time = time.time()

    addr = (LAPTOP_IP, LAPTOP_PORT)  # Laptop address for sending frames

    while True:
        ret, frame = cap.read()
        if not ret:
            print("[WARN] Failed to grab frame.")
            break

        # Start FPS timing for unencrypted video
        frame_start_time = time.time()

        # Display the unencrypted video stream
        cv2.imshow("Unencrypted Live Stream", frame)
        frame_count_unencrypted += 1

        # Compress to JPEG
        success, jpeg_data = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY])
        if not success:
            print("[WARN] JPEG encoding failed.")
            continue

        # Benchmark: Start encryption and sending timer
        encrypt_send_start_time = time.time()

        # Prepare for encryption
        plaintext = jpeg_data.tobytes()
        nonce = os.urandom(16)
        ciphertext = ascon_encrypt(shared_key, nonce, b"", plaintext)

        # Send encrypted video data
        frame_size = len(ciphertext)
        s.sendto(struct.pack("!I", frame_size), addr)
        s.sendto(nonce, addr)
        send_in_chunks(s, ciphertext, chunk_size=CHUNK_SIZE, addr=addr)

        # Benchmark: End encryption and sending timer
        encrypt_send_end_time = time.time()
        encrypt_send_time = encrypt_send_end_time - encrypt_send_start_time

        # Log the time to encrypt and send
        print(f"[BENCHMARK] Time to encrypt and send frame: {encrypt_send_time:.6f} seconds")
        with open(log_file, mode="a", newline="") as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow([datetime.now(), "Encryption & Send Time", f"{encrypt_send_time:.6f}"])

        # End FPS timing for encrypted frame
        frame_end_time = time.time()
        frame_count_encrypted += 1

        # Display FPS benchmarks every 5 seconds
        elapsed_time = frame_end_time - fps_start_time
        if elapsed_time >= 5.0:
            fps_unencrypted = frame_count_unencrypted / elapsed_time
            fps_encrypted = frame_count_encrypted / elapsed_time

            # Display in terminal
            print(f"[INFO] Unencrypted Video FPS: {fps_unencrypted:.2f}")
            print(f"[INFO] Encrypted Video FPS: {fps_encrypted:.2f}")

            # Log FPS to CSV
            with open(log_file, mode="a", newline="") as file:
                csv_writer = csv.writer(file)
                csv_writer.writerow([datetime.now(), "Unencrypted FPS", f"{fps_unencrypted:.2f}"])
                csv_writer.writerow([datetime.now(), "Encrypted FPS", f"{fps_encrypted:.2f}"])

            # Reset FPS counters
            fps_start_time = frame_end_time
            frame_count_encrypted = 0
            frame_count_unencrypted = 0

        if cv2.waitKey(1) & 0xFF == ord('q'):
            break

        # Frame interval control
        time.sleep(FRAME_INTERVAL)

# ----------------------------------------------------------------------
# Main Pi Script
# ----------------------------------------------------------------------
def main():
    # Initialize CSV file for logging
    global log_file
    log_file = "pi_benchmark_log.csv"
    with open(log_file, mode="w", newline="") as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow(["Timestamp", "Metric", "Value"])  # CSV header row

    # 1) Connect to Wi-Fi
    connect_to_router()

    # 2) Set up UDP socket
    print("[INFO] Setting up UDP socket...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # No need to connect for UDP; just set up the socket
    print(f"[INFO] UDP socket ready to send to {LAPTOP_IP}:{LAPTOP_PORT}")

    # ------------------------------------------------------------------
    # 3) RSA + ECDH Key Exchange
    # ------------------------------------------------------------------
    key_exchange_start = time.time()  # Start key exchange timing

    pi_rsa_key = RSA.generate(2048)
    pi_rsa_pubkey = pi_rsa_key.publickey().export_key()
    s.sendto(struct.pack("!I", len(pi_rsa_pubkey)), (LAPTOP_IP, LAPTOP_PORT))
    s.sendto(pi_rsa_pubkey, (LAPTOP_IP, LAPTOP_PORT))

    laptop_rsa_len_data, addr = s.recvfrom(4)
    laptop_rsa_len = struct.unpack("!I", laptop_rsa_len_data)[0]
    laptop_rsa_pub, addr = s.recvfrom(laptop_rsa_len)

    lap_rsa = RSA.import_key(laptop_rsa_pub)

    pi_ec_priv = ec.generate_private_key(ec.SECP256R1())
    pi_ec_pub_raw = pi_ec_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    cipher_rsa_lap = PKCS1_OAEP.new(lap_rsa)
    enc_pi_ec = cipher_rsa_lap.encrypt(pi_ec_pub_raw)
    s.sendto(struct.pack("!I", len(enc_pi_ec)), addr)
    s.sendto(enc_pi_ec, addr)

    lap_ec_len_data, addr = s.recvfrom(4)
    lap_ec_len = struct.unpack("!I", lap_ec_len_data)[0]
    enc_lap_ec, addr = s.recvfrom(lap_ec_len)

    cipher_rsa_pi = PKCS1_OAEP.new(pi_rsa_key)
    dec_lap_ec = cipher_rsa_pi.decrypt(enc_lap_ec)

    lap_ec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dec_lap_ec)

    shared_secret = pi_ec_priv.exchange(ECDH(), lap_ec_pub)
    shared_key = sha256(shared_secret).digest()[:16]

    key_exchange_end = time.time()  # End key exchange timing
    key_exchange_time = key_exchange_end - key_exchange_start
    print(f"[BENCHMARK] Key exchange time: {key_exchange_time:.6f} seconds")

    # Log key exchange time to CSV
    with open(log_file, mode="a", newline="") as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow([datetime.now(), "Key Exchange Time", f"{key_exchange_time:.6f}"])

    print("[INFO] Shared key established for real-time streaming.")

    # ------------------------------------------------------------------
    # 4) Start streaming, displaying, and sending video
    # ------------------------------------------------------------------
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Could not open webcam (check index or /dev/videoX).")
        s.close()
        return

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, CAP_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, CAP_HEIGHT)

    # Start the thread for capturing, displaying, and sending
    stream_thread = threading.Thread(target=capture_display_and_send, args=(s, cap, shared_key), daemon=True)
    stream_thread.start()
    stream_thread.join()

    # Release resources
    cap.release()
    s.close()
    cv2.destroyAllWindows()
    print("[INFO] Connection closed.")

if __name__ == "__main__":
    main()
