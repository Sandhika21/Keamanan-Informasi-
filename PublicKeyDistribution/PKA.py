from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json
import socket
from threading import Thread
import os
import time 

class PKA:
    def __init__(self, host='127.0.0.1', port=7632):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.load_keys()

    def load_keys(self):
        try:
            if not os.path.exists('pka_private_key.pem') or not os.path.exists('pka_public_key.pem'):
                print("Keys not found. Generating new keys...")
                self.generate_keys()
            with open('pka_private_key.pem', 'rb') as priv_file:
                self.private_key = RSA.import_key(priv_file.read())
            with open('pka_public_key.pem', 'rb') as pub_file:
                self.public_key = RSA.import_key(pub_file.read())
            self.cipher = PKCS1_OAEP.new(self.private_key)
            print("PKA keys loaded successfully.")
        except Exception as e:
            print(f"Error loading keys: {e}")
            raise

    def generate_keys(self):
        try:
            key = RSA.generate(2048)
            private_key = key.export_key()
            public_key = key.publickey().export_key()
            with open('pka_private_key.pem', 'wb') as priv_file:
                priv_file.write(private_key)
            with open('pka_public_key.pem', 'wb') as pub_file:
                pub_file.write(public_key)
            print("New RSA keys have been generated and saved.")
        except Exception as e:
            print(f"Error generating keys: {e}")
            raise

    def listen(self):
        print(f"PKA running on {self.host}:{self.port}")
        while True:
            client_socket, client_address = self.socket.accept()
            print(f"Connection from: {client_address}")
            Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            message = client_socket.recv(1024).decode()
            print(f"Raw message received at PKA: {message}")  # Log data mentah
            msg_dict = json.loads(message)
            if msg_dict.get('Message') == 'Request':
                # Kirim kembali public key
                response = json.dumps({
                    'Content': self.public_key.export_key().decode()
                })
                client_socket.sendall((response + '\n').encode())
                print("Public key sent to Initiator.")
            else:
                print(f"Invalid message received: {msg_dict}")
        except Exception as e:
            print(f"Error handling client at PKA: {e}")
        finally:
            client_socket.close()

    def connect_to_server(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
                client_socket.connect(('127.0.0.1', 12345)) 
                registration_message = json.dumps({
                    'Message': 'PKA Registration',
                    'Time Stamp': time.asctime(time.localtime(time.time())),
                    'From': ('127.0.0.1', 7632),
                    'To': ('127.0.0.1', 12345),
                    'Content': None
                })
                client_socket.sendall((registration_message + '\n').encode())
                print("PKA successfully registered with the server.")
        except Exception as e:
            print(f"Error connecting to server: {e}")

if __name__ == "__main__":
    pka = PKA()
    pka.connect_to_server()  
    pka.listen()
