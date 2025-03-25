import socket
import sys
import os
import time

from multiprocessing import Process

from drone_control import (
    connect_to_drone,
    request_message_interval,
    arm_vehicle,
    disarm_vehicle,
    takeoff,
    land,
    return_to_launch,
    move_ned_offset,
    parse_distance_value,
    get_position,
    survey,
    CONNECTION_TYPE,  # from drone_controls
    DEFAULT_TAKEOFF_ALT,
    DEFAULT_SURVEY_DURATION
)
from chirp_receive import start_chirp_failsafe
from Key_Exch_UAV import uav_exch
from Key_Exch_UGV import ugv_exch
from socket_comms import send_message
from socket_comms import receive_message
from socket_comms import receive_message_from_fprime
from log_send import send_encrypted_log
from ascon import ascon_decrypt

def check_failsafe():
    return os.path.exists("/tmp/failsafe_trigger.flag")

def handle_command(cmd, drone):
    """
    Interpret the incoming command string and call the appropriate function
    from the drone-controls library.
    """
    cmd = cmd.strip().lower()
    if cmd.startswith("arm"):
        arm_vehicle(drone)
        takeoff(drone, DEFAULT_TAKEOFF_ALT)
        return "[INFO] Armed and took off."
    elif cmd.startswith("forward"):
        dist = parse_distance_value(cmd) or 1
        move_ned_offset(drone, dist, 0, 0)
        return f"[INFO] Moved forward {dist}m."
    elif cmd.startswith("backward"):
        dist = parse_distance_value(cmd) or 1
        move_ned_offset(drone, -dist, 0, 0)
        return f"[INFO] Moved backward {dist}m."
    elif cmd.startswith("left"):
        dist = parse_distance_value(cmd) or 1
        move_ned_offset(drone, 0, -dist, 0)
        return f"[INFO] Moved left {dist}m."
    elif cmd.startswith("right"):
        dist = parse_distance_value(cmd) or 1
        move_ned_offset(drone, 0, dist, 0)
        return f"[INFO] Moved right {dist}m."
    elif cmd.startswith("up"):
        dist = parse_distance_value(cmd) or 1
        move_ned_offset(drone, 0, 0, -dist)
        return f"[INFO] Moved up {dist}m."
    elif cmd.startswith("down"):
        dist = parse_distance_value(cmd) or 1
        move_ned_offset(drone, 0, 0, dist)
        return f"[INFO] Moved down {dist}m."
    elif cmd == "land":
        land(drone)
        disarm_vehicle(drone)
        return "[INFO] Landed and disarmed."
    elif cmd == "rtl":
        return_to_launch(drone)
        disarm_vehicle(drone)
        return "[INFO] Returned to launch and disarmed."
    elif cmd == "disarm":
        disarm_vehicle(drone)
        return "[INFO] Disarmed."
    elif cmd == "pos":
        get_position(drone)
        return "[INFO] Position printed."
    elif cmd.startswith("survey"):
        duration = parse_distance_value(cmd) or DEFAULT_SURVEY_DURATION
        survey(drone, duration)
        return "[INFO] 360 survey done."
    #elif cmd.startswith("Stream"):
        #duration = parse_distance_value(cmd) or DEFAULT_SURVEY_DURATION
        #stream command from nachos thing
        #return "[INFO] Stream Started"
    else:
        return "[WARNING] Unknown command."

def start_dc_rx():
    HOST = "0.0.0.0"
    PORT = 3030
    
    # start failsafe
    failsafe_proc = Process(target=start_chirp_failsafe(shared_key))
    failsafe_proc.start()

    # start control socket
    server_c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_c.bind((HOST, PORT))

    #start drone connection
    #change drone control type to USB
    drone = connect_to_drone(CONNECTION_TYPE)
    request_message_interval(drone, 33, 1.0)
    print("Drone Connected")
    while True:
        fs_flag = check_failsafe()
        if fs_flag == True:
            #send_to_logger("Failsafe Detected")
            return_to_launch(drone)
            disarm_vehicle(drone)
            print("[FAILSAFE] Triggered. Drone returning to launch and disarming.")
            break
        #receive encrypted messages
        nonce, cipher, _ = receive_message_from_fprime(server_c)
        recv_cmnd = ascon_decrypt(shared_key, nonce, b"", cipher)
        print(f"[RECEIVED CMND]: {recv_cmnd.decode()}")
        response = handle_command(recv_cmnd.decode(), drone)
        send_encrypted_log(response, shared_key)
        #response_time = time.time()
        #send response + time to UGV log port
        #also write UGV log port script
        print(response)
        #send_to_logger(response)
    



shared_key = uav_exch()
print("got the shared key")

start_dc_rx()
