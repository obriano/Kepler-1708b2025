# ugv_log_receiver.py
import socket
import os
import datetime
from ascon import ascon_decrypt
from socket_comms import receive_message_from_fprime

# === CONFIG ===
LOG_PORT = 5050
BUFFER_SIZE = 1024
SHARED_KEY_PATH = "/tmp/shared_key.bin"
LOG_FILE = "/home/ugv/logs/flight_session_log.txt"

def load_shared_key():
    with open(SHARED_KEY_PATH, "rb") as f:
        return f.read()

def log_response_to_file(response):
    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a") as f:
        f.write(f"{timestamp} {response}\n")
    print(f"[LOGGED] {timestamp} {response}")

def start_log_receiver():
    shared_key = load_shared_key()

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_sock.bind(("0.0.0.0", LOG_PORT))
    print(f"[INFO] UGV log receiver listening on port {LOG_PORT}...")

    try:
        while True:
            nonce, _ = receive_message(server_c)
            cipher, _ = receive_message(server_c)
            try:
                decrypted = ascon_decrypt(shared_key, nonce, b"", cipher)
                response = decrypted.decode()
                log_response_to_file(response)
            except Exception as e:
                print(f"[ERROR] Failed to decrypt or log response: {e}")
    except KeyboardInterrupt:
        print("[INFO] Log receiver shutting down.")
        server_sock.close()

if __name__ == "__main__":
    start_log_receiver()
