#UAV Side RECEIVES CHIRPS (SHOULD BE LISTENING)
import socket
import sys
import os
import struct
import time

from Key_Exch_UAV import uav_exch
from Key_Exch_UGV import ugv_exch
from socket_comms import send_message
from socket_comms import receive_message
from ascon import ascon_decrypt

def start_chirp_failsafe(shared_key):
    HOST = '0.0.0.0'
    PORT = 9090
    TIMEOUT_SEC = 5

    #shared_key = ugv_exch()
    #print("got shared key")

    server_c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_c.bind((HOST, PORT))
    server_c.settimeout(1.0)

    print("receiving chirps")

    last_chirp = time.time()

    while True:
        try:
            nonce, _ = receive_message(server_c)
            cipher, _ = receive_message(server_c)
            rec_chirp = ascon_decrypt(shared_key, nonce, b"", cipher)
            print(f"[RECEIVED CHIRP]: {int.from_bytes(rec_chirp, 'big')}")
            
            last_chirp = time.time()
        except socket.timeout:
            pass
        
        if time.time() - last_chirp  > TIMEOUT_SEC:
            print("Fail-safe triggered")
            with open("/tmp/failsafe_trigger.flag", "w") as f:
                    f.write("chirp timeout failsafe")
            last_chirp = time.time()  # prevent constant retriggering
    
#start_chirp_failsafe()
