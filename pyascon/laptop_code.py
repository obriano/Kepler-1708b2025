import socket
import struct
import cv2
import os
import numpy as np
import time  
import csv  
from datetime import datetime  
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
LAPTOP_IP = "0.0.0.0"  
LAPTOP_PORT = 8888
CHUNK_SIZE = 512 

# ----------------------------------------------------------------------
# Socket Helpers
# ----------------------------------------------------------------------
def recv_in_chunks(sock, length, chunk_size=CHUNK_SIZE):
    """Receives data in smaller chunks for smoother streaming."""
    data = b""
    while len(data) < length:
        chunk = sock.recv(min(chunk_size, length - len(data)))
        if not chunk:
            raise ConnectionError("Connection lost while receiving data.")
        data += chunk
    return data

# ----------------------------------------------------------------------
# Main Laptop Script
# ----------------------------------------------------------------------
def main():
    # Initialize CSV file for logging
    log_file = "laptop_benchmark_log.csv"
    with open(log_file, mode="w", newline="") as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow(["Timestamp", "Metric", "Time (seconds)"])  

    print("[INFO] Starting server on laptop...")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1000000)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1000000)
    
    s.bind((LAPTOP_IP, LAPTOP_PORT))
    s.listen(1)
    print(f"[INFO] Waiting for connection on {LAPTOP_IP}:{LAPTOP_PORT}...")
    
    # Measure connection time
    start_time = time.time()
    conn, addr = s.accept()
    end_time = time.time()
    connection_time = end_time - start_time
    print(f"[BENCHMARK] Time to establish connection: {connection_time:.6f} seconds")
    
    # Log connection time to CSV
    with open(log_file, mode="a", newline="") as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow([datetime.now(), "Connection Time", f"{connection_time:.6f}"])
    
    print(f"[INFO] Connected by {addr}")
    
    # ------------------------------------------------------------------
    # 1) RSA + ECDH Key Exchange
    # ------------------------------------------------------------------
    key_exchange_start = time.time()  # Start key exchange timing

    laptop_rsa_key = RSA.generate(2048)
    laptop_rsa_pubkey = laptop_rsa_key.publickey().export_key()
    
    conn.sendall(struct.pack("!I", len(laptop_rsa_pubkey)))
    conn.sendall(laptop_rsa_pubkey)
    
    pi_rsa_len = struct.unpack("!I", recv_in_chunks(conn, 4))[0]
    pi_rsa_pubkey = recv_in_chunks(conn, pi_rsa_len)
    
    laptop_ec_priv = ec.generate_private_key(ec.SECP256R1())
    laptop_ec_pub_raw = laptop_ec_priv.public_key().public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    
    pi_rsa = RSA.import_key(pi_rsa_pubkey)
    cipher_rsa_pi = PKCS1_OAEP.new(pi_rsa)
    enc_lap_ec = cipher_rsa_pi.encrypt(laptop_ec_pub_raw)
    
    conn.sendall(struct.pack("!I", len(enc_lap_ec)))
    conn.sendall(enc_lap_ec)
    
    pi_ec_len = struct.unpack("!I", recv_in_chunks(conn, 4))[0]
    enc_pi_ec = recv_in_chunks(conn, pi_ec_len)
    
    cipher_rsa = PKCS1_OAEP.new(laptop_rsa_key)
    dec_pi_ec = cipher_rsa.decrypt(enc_pi_ec)
    
    pi_ec_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), dec_pi_ec)
    shared_secret = laptop_ec_priv.exchange(ECDH(), pi_ec_pub)
    shared_key = sha256(shared_secret).digest()[:16]

    key_exchange_end = time.time()  # End key exchange timing
    key_exchange_time = key_exchange_end - key_exchange_start
    print(f"[BENCHMARK] Key exchange time: {key_exchange_time:.6f} seconds")
    
    # Log key exchange time to CSV
    with open(log_file, mode="a", newline="") as file:
        csv_writer = csv.writer(file)
        csv_writer.writerow([datetime.now(), "Key Exchange Time", f"{key_exchange_time:.6f}"])
    
    print("[INFO] Shared key established for real-time decryption.")
    
    # ------------------------------------------------------------------
    # 2) Receive and decrypt video frames
    # ------------------------------------------------------------------
    while True:
        try:
            frame_start_time = time.time()  # Start frame timing
            frame_size_data = conn.recv(4)
            if not frame_size_data:
                break
            frame_size = struct.unpack("!I", frame_size_data)[0]
            
            nonce = recv_in_chunks(conn, 16)
            ciphertext = recv_in_chunks(conn, frame_size, CHUNK_SIZE)
            
            decrypted_data = ascon_decrypt(shared_key, nonce, b"", ciphertext)
            frame = np.frombuffer(decrypted_data, dtype=np.uint8)
            frame = cv2.imdecode(frame, cv2.IMREAD_COLOR)
            
            frame_end_time = time.time()  # End frame timing
            frame_time = frame_end_time - frame_start_time
            print(f"[BENCHMARK] Time to decrypt and display frame: {frame_time:.6f} seconds")
            
            # Log frame time to CSV
            with open(log_file, mode="a", newline="") as file:
                csv_writer = csv.writer(file)
                csv_writer.writerow([datetime.now(), "Decryption & Display Time", f"{frame_time:.6f}"])
            
            if frame is not None:
                cv2.imshow("Live Stream", frame)
            else:
                print("[WARN] Decoded frame is None")
            
            if cv2.waitKey(1) & 0xFF == ord('q'):
                break
        except ConnectionError:
            print("[ERROR] Connection lost. Exiting...")
            break
    
    conn.close()
    s.close()
    cv2.destroyAllWindows()
    print("[INFO] Connection closed.")
    
if __name__ == "__main__":
    main()
