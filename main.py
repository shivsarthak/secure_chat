import socket
import sys
import os
import threading
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


def encrypt(key:bytes, plain_text:str):
    """Takes two parameters (bytes[16 bytes],string) and returns ciphertext in hex"""
    cipher = AES.new(key,AES.MODE_ECB)
    cipher_text = cipher.encrypt(pad(bytes(plain_text,'utf-8'),AES.block_size))
    return cipher_text


def decrypt(key:bytes, ciphertext:bytes):
    """Takes two parameters (bytes[16 bytes],bytes) and returns plaintext"""
    cipher = AES.new(key,AES.MODE_ECB)
    plain_text = unpad(cipher.decrypt(ciphertext),AES.key_size[0])
    return plain_text


def receive_all(sock: socket):
    buff_size = 4096
    data = b''
    while True:
        part = sock.recv(buff_size)
        data += part
        if len(part) < buff_size:
            break
    return data


def import_public_key(pkeydata):
    public_key = RSA.importKey(pkeydata)
    return public_key


def encrypt_with_public_key(data, public_key):
    encryptor = PKCS1_OAEP.new(public_key)
    return encryptor.encrypt(data)


class RsaKeys:
    def __init__(self):
        self.private_key = RSA.generate(2048)
        self.public_key = self.private_key.publickey()

    def export_keys(self):
        private_file = open('private_key.pem', 'w')
        private_file.write(self.private_key.exportKey(format='PEM').decode('utf-8'))
        public_file = open('public_key.pem', 'w')
        public_file.write(self.public_key.exportKey(format='PEM').decode('utf-8'))

    def decrypt_with_private_key(self, cipher_text):
        decryptor = PKCS1_OAEP.new(self.private_key)
        return decryptor.decrypt(cipher_text)


class Listener:
    def __init__(self, host, port):
        self.asymmetric_keys = RsaKeys()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen()
        print("Listening for Client 🌏")
        self.sock = self.sock.accept()[0]
        self.sock.sendall(self.asymmetric_keys.public_key.exportKey(format='PEM'))
        encrypted_session_key = receive_all(self.sock)
        session_key = self.asymmetric_keys.decrypt_with_private_key(encrypted_session_key)
        self.session = Session(session_key,self.sock)


class Client:
    def __init__(self, address, port):
        self.session_key = os.urandom(16)
        print("Connecting to Listener 🌏")
        self.asymmetric_keys = RsaKeys()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((address, port))
        pubkeydata = receive_all(self.sock)
        self.listener_public_key = import_public_key(pubkeydata)
        encrypted_session_key = encrypt_with_public_key(self.session_key,self.listener_public_key)
        self.sock.sendall(encrypted_session_key)
        self.session = Session(self.session_key, self.sock)


class Session:
    def __init__(self,key,sock:socket):
        print("Session Created ✅")
        self.session_active = True
        self.session_key = key
        self.session_socket = sock
        try:
            background_thread = threading.Thread(target=self.receive)
            background_thread.daemon = True
            background_thread.start()
            while True:
                self.send(input())
        except (KeyboardInterrupt, SystemExit):
            self.session_active = False
            background_thread.join()
            sys.exit()

    def send(self,data):
        encrypted_data = encrypt(self.session_key,data)
        self.session_socket.sendall(encrypted_data)

    def receive(self):
        while self.session_active:
            encrypted_message = receive_all(self.session_socket)
            print((decrypt(self.session_key,encrypted_message)).decode('utf-8'))


if __name__ == '__main__':
    if len(sys.argv)<4:
        print("Example Usage-\nFor listener:  python3 main.py -l 127.0.0.1 65432\nFor client:  python3 main.py "
              "-c 127.0.0.1 65432")
        sys.exit(1)
    if sys.argv[1] in ['-client','-c','c']:
        Client(sys.argv[2],int(sys.argv[3]))
    elif sys.argv[1] in ['-listener','-l','l']:
        Listener(sys.argv[2],int(sys.argv[3]))
