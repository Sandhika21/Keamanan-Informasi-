import function
import json
import socket
from threading import Thread

class Responder():
    def __init__(self, host='127.0.0.1', port=64654):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host, self.port = host, port
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        self.clients = {}
        self.des_key = None
        self.e, self.d, self.n = function.responder_key_pair()

    def listen(self):
        while True:
            client_socket, client_address = self.socket.accept()
            self.clients[client_address] = client_socket
            print(f"Connection from: {client_address}")
            Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            message = self.receive_message(client_socket)
            msg_dict = json.loads(message)
            if msg_dict['Message'] == 'to Responder':
                content = json.loads(function.encrypt(msg_dict['Content'], self.d, self.n))
                N1 = content['myN']
                response_content = json.dumps({'myN': N1, 'yourN': N1})
                encrypted_response = function.encrypt(response_content, content['Public Key'][0], content['Public Key'][1])
                response_message = self.create_message('Response', encrypted_response)
                client_socket.sendall(response_message.encode())
            elif msg_dict['Message'] == 'session key':
                encrypted_des_key = msg_dict['Content']
                des_key_content = json.loads(function.encrypt(encrypted_des_key, self.d, self.n))
                self.des_key = des_key_content['des_key']
                print(f"Received DES key: {self.des_key}")
        except Exception as e:
            print(f"Error handling client: {e}")
            client_socket.close()

    def receive_message(self, client_socket):
        data = b''
        try:
            while True:
                packet = client_socket.recv(1024)
                if not packet:
                    break
                data += packet
        except Exception as e:
            print(f"Error receiving message: {e}")
        return data.decode()

    def create_message(self, message, content=None):
        return json.dumps({
            'Message': message,
            'Content': content
        })

responder = Responder()
responder.listen()
