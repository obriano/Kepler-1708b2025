import socket
import struct
import cv2
import os
import numpy as np
import time  # For benchmarking
import csv  # For CSV logging
from datetime import datetime  # For timestamps

from ascon import ascon_decrypt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDH
from hashlib import sha256

# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
LAPTOP_IP = "0.0.0.0"  # Listen on all available interfaces
LAPTOP_PORT = 8888
CHUNK_SIZE = 512  # Optimized chunk size for smoother streaming

# ----------------------------------------------------------------------
# Initialize CSV Logging
# ----------------------------------------------------------------------
log_file = "laptop_benchmark_log.csv"

def log_to_csv(metric, value):
    """Logs benchmark data to CSV in real-time."""
    with open(log_file, mode="a", newline="") as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow([datetime.now(), metric, value])

# Create CSV file with headers at startup
with open(log_file, mode="w", newline="") as file:
    csv_writer = csv.writer(file)
    csv_writer.writerow(["Timestamp", "Metric", "Value"])  # CSV header row

# ----------------------------------------------------------------------
# Socket Helpers
# ----------------------------------------------------------------------
def recv_in_chunks(sock, length, chunk_size=CHUNK_SIZE):
    """Receives data in smaller chunks for smoother streaming."""
    data = b""
    while len(data) < length:
        chunk, addr = sock.recvfrom(min(chunk_size, length - len(data)))
        if not chunk:
            raise ConnectionError("Connection lost while receiving data.")
        data += chunk
    return data

# ----------------------------------------------------------------------
# Main Laptop Script
# ----------------------------------------------------------------------
def main():
    print("[INFO] Starting UDP server...")
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((LAPTOP_IP, LAPTOP_PORT))
    print(f"[INFO] Listening for UDP packets on {LAPTOP_IP}:{LAPTOP_PORT}...")

    # ------------------------------------------------------------------
    # 1) RSA + ECDH Key Exchange
    # ------------------------------------------------------------------
    key_exchange_start = time.time()

    # Receive RSA public key from Pi
    pi_rsa_len_data, addr = s.recvfrom(4)
    pi_rsa_len = struct.unpack("!I", pi_rsa_len_data)[0]
    pi_rsa_pubkey, addr = s.recvfrom(pi_rsa_len)

    laptop_rsa_key = RSA.generate(2048)
    laptop_rsa_pubkey = laptop_rsa_key.publickey().export_key()

    s.sendto(struct.pack("!I", len(laptop_rsa_pubkey)), addr)
    s.sendto(laptop_rsa_pubkey, addr)

    enc_pi_ec_len_data, addr = s.recvfrom(4)
    enc_pi_ec_len = struct.unpack("!I", enc_pi_ec_len_data)[0]
    enc_pi_ec, addr = s.recvfrom(enc_pi_ec_len)

    cipher_rsa = PKCS1_OAEP.new(laptop_rsa_key)
    dec_pi_ec = cipher_rsa.decrypt(enc_pi_ec)

    pi_ec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dec_pi_ec)

    laptop_ec_priv = ec.generate_private_key(ec.SECP256R1())
    laptop_ec_pub_raw = laptop_ec_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    cipher_rsa_pi = PKCS1_OAEP.new(RSA.import_key(pi_rsa_pubkey))
    enc_lap_ec = cipher_rsa_pi.encrypt(laptop_ec_pub_raw)
    s.sendto(struct.pack("!I", len(enc_lap_ec)), addr)
    s.sendto(enc_lap_ec, addr)

    shared_secret = laptop_ec_priv.exchange(ECDH(), pi_ec_pub)
    shared_key = sha256(shared_secret).digest()[:16]

    print(f"[DEBUG] Shared Key (Laptop): {shared_key.hex()}")  # Debug Key

    key_exchange_end = time.time()
    key_exchange_time = key_exchange_end - key_exchange_start
    print(f"[BENCHMARK] Key exchange time: {key_exchange_time:.6f} seconds")
    log_to_csv("Key Exchange Time", f"{key_exchange_time:.6f}")

    print("[INFO] Shared key established for real-time decryption.")

    # ------------------------------------------------------------------
    # 2) Receive, decrypt video frames, and calculate FPS
    # ------------------------------------------------------------------
    frame_count = 0
    fps_start_time = time.time()

    while True:
        try:
            frame_start_time = time.time()

            frame_size_data, addr = s.recvfrom(4)
            frame_size = struct.unpack("!I", frame_size_data)[0]

            nonce = recv_in_chunks(s, 16, CHUNK_SIZE)
            ciphertext = recv_in_chunks(s, frame_size, CHUNK_SIZE)

            # Decrypt Frame
            decrypt_start = time.time()
            decrypted_data = ascon_decrypt(shared_key, nonce, b"", ciphertext)

            if not decrypted_data:
                print("[ERROR] Decryption failed. Skipping frame.")
                log_to_csv("Decryption Error", "Frame discarded")
                continue

            frame = np.frombuffer(decrypted_data, dtype=np.uint8)
            frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)

            if frame is None:
                print("[ERROR] Frame decoding failed. Possible corruption.")
                log_to_csv("Frame Decoding Error", "Corrupted Frame")
                continue

            decrypt_end = time.time()
            decryption_time = decrypt_end - decrypt_start
            frame_time = decrypt_end - frame_start_time

            # Display Video Frame (Now inside main loop)
            cv2.imshow("Live Encrypted Stream", frame)
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break

            # Benchmarking
            print(f"[BENCHMARK] Decryption Time: {decryption_time:.6f} sec | Frame Time: {frame_time:.6f} sec")
            log_to_csv("Decryption Time", f"{decryption_time:.6f}")
            log_to_csv("Frame Processing Time", f"{frame_time:.6f}")

            frame_count += 1
            elapsed_time = time.time() - fps_start_time
            if elapsed_time >= 5.0:
                fps = frame_count / elapsed_time
                print(f"[INFO] FPS: {fps:.2f}")
                log_to_csv("FPS", f"{fps:.2f}")

                fps_start_time = time.time()
                frame_count = 0

        except Exception as e:
            print(f"[ERROR] Exception occurred: {e}")
            log_to_csv("Exception", str(e))
            break

    s.close()
    cv2.destroyAllWindows()
    print("[INFO] UDP server stopped.")

if __name__ == "__main__":
    main()
