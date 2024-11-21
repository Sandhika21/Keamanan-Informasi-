import socket
import json
from threading import Thread
import function

class PKA():
    def __init__(self, host='127.0.0.1', port=7632):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host, self.port = host, port
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)# Key: client ID, Value: public key
        self.public_keys = {
            'Initiator' : function.initiator_key_pair(),
            'Responder' : function.responder_key_pair()
        }  
        self.e, self.d, self.n = function.PKA_key_pair()

    def listen(self):
        while True:
            client_socket, client_address = self.socket.accept()
            print(f"Connection from: {client_address}")
            Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            message = self.receive_message(client_socket)
            msg_dict = json.loads(message)
            if msg_dict['Message'] == 'request key':
                client_id = msg_dict['Client ID']
                if client_id in self.public_keys:
                    public_key = json.dumps({
                        'Public Key' : self.public_keys[client_id]
                    })
                    encrypted_key = function.encrypt(public_key, self.d, self.n)
                    response_message = self.create_message('key', encrypted_key)
                    client_socket.sendall(response_message.encode())
                else:
                    encrypted_error = function.encrypt('Client ID not found', self.d, self.n)
                    response_message = self.create_message('error', encrypted_error)
                    client_socket.sendall(response_message.encode())
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

pka = PKA()
pka.listen()