# === uav_log_sender.py ===
# Call send_encrypted_log(response, shared_key) from within dc_rx.py

import os
import socket
from ascon import ascon_encrypt
from socket_comms import send_message

UGV_IP = "192.168.1.100"  # Replace with UGV IP if static
LOG_PORT = 6060

def send_encrypted_log(response: str, shared_key: bytes):
    """
    Encrypts and sends the response log to the UGV.
    """
    addr = (UGV_IP, LOG_PORT)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    nonce = os.urandom(16)
    cipher = ascon_encrypt(shared_key, nonce, b"", response.encode())

    send_message(sock, addr, nonce + cipher)
    sock.close()