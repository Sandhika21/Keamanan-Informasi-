import socket
import json
from threading import Thread
import function

class PKA():
    def __init__(self, host='127.0.0.1', port=2345):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.current_client = None
        self.host, self.port = host, port
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)# Key: client ID, Value: public key
        self.public_keys = {
            'Initiator' : function.initiator_key_pair(),
            'Responder' : function.responder_key_pair()
        }  
        self.Clients = {}
        self.e, self.d, self.n = function.PKA_key_pair()

    def listen(self):
        while True:
            client_socket, client_address = self.socket.accept()
            msg_id = client_socket.recv(1024).decode()
            client_id = json.loads(msg_id)
            self.Clients[client_id['Client ID']] = client_socket    
            
            print(f"Connection from: {client_address}")
            Thread(target=self.handle_client, args=(client_socket,)).start()

    def handle_client(self, client_socket):
        try:
            print('pka')
            message = client_socket.recv(1024).decode()
            msg_dict = json.loads(message)
            print(msg_dict)
            if msg_dict['Message'] == 'request key':
                client_id = msg_dict['Client ID']
                print(client_id)
                if client_id in self.public_keys:
                    public_key = json.dumps({
                        'Public Key' : self.public_keys[client_id]
                    })
                    encrypted_key = function.encrypt(public_key, self.d, self.n)
                    response_message = self.create_message('key', encrypted_key)
                    client_socket.send(response_message.encode())
                else:
                    encrypted_error = function.encrypt('Client ID not found', self.d, self.n)
                    response_message = self.create_message('error', encrypted_error)
                    client_socket.send(response_message.encode())
        except Exception as e:
            print(f"Error handling client: {e}")
            client_socket.close()

    def create_message(self, message, content=None):
        return json.dumps({
            'Message': message,
            'Content': content
        })

pka = PKA()
pka.listen()
