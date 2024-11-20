import socket
import json
import function

class Responder():
    def __init__(self, host='127.0.0.1', port=64654, pka_host='127.0.0.1', pka_port=7632):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host = host
        self.port = port
        self.pka_host = pka_host
        self.pka_port = pka_port
        self.e, self.d, self.n = function.responder_key_pair()
        self.PKA_e, _, self.PKA_n = function.PKA_key_pair()
        self.des_key = None
        self.des = None
    
    def connect_to_pka(self):
        self.socket.connect((self.pka_host, self.pka_port))
        self.request_public_key()

    def request_public_key(self):
        request_message = "Request"
        self.socket.sendall(request_message.encode())
        response = self.socket.recv(1024).decode()
        self.handle_pka_response(response)

    def handle_pka_response(self, response):
        pka_data = json.loads(response)
        self.PKA_e, self.PKA_n = pka_data['Public Key']

    def receive_des_key(self):
        encrypted_des_key = self.socket.recv(1024).decode()
        des_key = function.encrypt(encrypted_des_key, self.d, self.n)
        self.des_key = json.loads(des_key)['des_key']
        self.des = function.DES_function(self.des_key)
    
    def decrypt_message(self, encrypted_message):
        return self.des.decrypt_message(encrypted_message)

    def start(self):
        self.connect_to_pka()
        self.receive_des_key()
  
        while True:
            encrypted_message = self.socket.recv(1024).decode()
            print(f"Pesan terenkripsi yang diterima: {encrypted_message}")
            decrypted_message = self.decrypt_message(encrypted_message)
            print(f"Pesan yang telah didekripsi: {decrypted_message}")

responder = Responder()
responder.start()
