## Lightweight Cryptographic Applications for Secure Robotic Systems
By Kepler 1708b
Reconfigurable Space Computing Lab @ Cal Poly Pomona

Team Members:
Omar Briano, Aaron Kernhoff, Ignacio DeJesus Velasco, Marshall Ung, Aidan Acheta, Nicolas Gomez, Cindy Chiu, Zaid Omar
Faculty Advisor: 
Professor: Mohamed El-Hadedy Aly

This repository contains all developmental subsystems for the proposed robotic system as submitted to NASAMINDs 2025 under the team name "Kepler-1708b"

Goal: To develop secure applications for heterogeneous robotic systems for the purpose of advancing unmanned terrain exploration for the NASA Artemis mission.

The complete system composes of a PYNQ-Z2 FPGA board utilizing Linux and F', JPL's flight framework, on a mobile chassis to represent a mobile ground station for a UAV, serving as the second half of the complete system. Communication remains secure between the two vehicles by utilizing the Ascon lightweight cipher and a hybrid RSA and Elliptic-Curve Diffie-Hellman for secure session key generation. Utilizing natural-language commands to control all subsystems allows for ease-of-operation with minimal training time.
