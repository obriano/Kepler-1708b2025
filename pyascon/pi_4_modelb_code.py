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
ROUTER_SSID = "Enter_Router_Info"
ROUTER_PASSWORD = "Enter_Router_Info"

LAPTOP_IP = "Enter Laptop IP"   
LAPTOP_PORT = 8888

FRAME_INTERVAL = 0.001  
CAP_WIDTH = 320
CAP_HEIGHT = 240
JPEG_QUALITY = 40  
CHUNK_SIZE = 512  

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
def send_in_chunks(sock, data, chunk_size=CHUNK_SIZE):
    """Sends data in smaller chunks for smoother transmission."""
    for i in range(0, len(data), chunk_size):
        sock.sendall(data[i:i + chunk_size])

# ----------------------------------------------------------------------
# Multi-threaded Frame Capture & Sending
# ----------------------------------------------------------------------
def capture_and_send(s, cap, shared_key):
    while True:
        ret, frame = cap.read()
        if not ret:
            print("[WARN] Failed to grab frame.")
            break

        frame_start_time = time.time()  # Start frame timing
        success, jpeg_data = cv2.imencode(".jpg", frame, [int(cv2.IMWRITE_JPEG_QUALITY), JPEG_QUALITY])
        if not success:
            print("[WARN] JPEG encoding failed.")
            continue

        plaintext = jpeg_data.tobytes()
        nonce = os.urandom(16)
        ciphertext = ascon_encrypt(shared_key, nonce, b"", plaintext)

        frame_size = len(ciphertext)
        s.sendall(struct.pack("!I", frame_size))
        s.sendall(nonce)
        send_in_chunks(s, ciphertext, chunk_size=CHUNK_SIZE)

        frame_end_time = time.time()  # End frame timing
        frame_time = frame_end_time - frame_start_time
        print(f"[BENCHMARK] Time to encrypt and send frame: {frame_time:.6f} seconds")

        # Log frame encryption and send time to CSV
        with open(log_file, mode="a", newline="") as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow([datetime.now(), "Encryption & Send Time", f"{frame_time:.6f}"])

        time.sleep(FRAME_INTERVAL)  # Adjust as needed

# ----------------------------------------------------------------------
# Main Pi Script
# ----------------------------------------------------------------------
def main():
    # Initialize CSV file for logging
    global log_file
    log_file = "pi_benchmark_log.csv"
    with open(log_file, mode="w", newline="") as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow(["Timestamp", "Metric", "Time (seconds)"])  

    # 1) Connect to Wi-Fi
    connect_to_router()

    # 2) Connect to laptop
    connection_start_time = time.time()  # Start connection timing
    print("[INFO] Connecting to laptop...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Increase TCP buffer size
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1000000)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1000000)

    s.connect((LAPTOP_IP, LAPTOP_PORT))
    connection_end_time = time.time()  # End connection timing
    laptop_connection_time = connection_end_time - connection_start_time
    print(f"[BENCHMARK] Time to connect to laptop: {laptop_connection_time:.6f} seconds")

    # Log laptop connection time to CSV
    with open(log_file, mode="a", newline="") as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow([datetime.now(), "Laptop Connection Time", f"{laptop_connection_time:.6f}"])

    # ------------------------------------------------------------------
    # 3) RSA + ECDH Key Exchange
    # ------------------------------------------------------------------
    key_exchange_start = time.time()  # Start key exchange timing

    lap_rsa_len = struct.unpack("!I", s.recv(4))[0]
    laptop_rsa_pub = s.recv(lap_rsa_len)

    pi_rsa_key = RSA.generate(2048)
    pi_rsa_pubkey = pi_rsa_key.publickey().export_key(format='PEM')
    pi_rsa_privkey = pi_rsa_key.export_key()

    s.sendall(struct.pack("!I", len(pi_rsa_pubkey)))
    s.sendall(pi_rsa_pubkey)

    lap_ec_len = struct.unpack("!I", s.recv(4))[0]
    enc_lap_ec = s.recv(lap_ec_len)

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(pi_rsa_privkey))
    dec_lap_ec = cipher_rsa.decrypt(enc_lap_ec)

    lap_ec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dec_lap_ec)

    pi_ec_priv = ec.generate_private_key(ec.SECP256R1())
    pi_ec_pub_raw = pi_ec_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    lap_rsa = RSA.import_key(laptop_rsa_pub)
    cipher_rsa_lap = PKCS1_OAEP.new(lap_rsa)
    enc_pi_ec = cipher_rsa_lap.encrypt(pi_ec_pub_raw)

    s.sendall(struct.pack("!I", len(enc_pi_ec)))
    s.sendall(enc_pi_ec)

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
    # 4) Start streaming in a separate thread
    # ------------------------------------------------------------------
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("[ERROR] Could not open webcam (check index or /dev/videoX).")
        s.close()
        return

    cap.set(cv2.CAP_PROP_FRAME_WIDTH, CAP_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, CAP_HEIGHT)

    stream_thread = threading.Thread(target=capture_and_send, args=(s, cap, shared_key), daemon=True)
    stream_thread.start()
    stream_thread.join()

    cap.release()
    s.close()
    print("[INFO] Connection closed.")

if __name__ == "__main__":
    main()
