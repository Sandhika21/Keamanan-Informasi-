import socket
from threading import Thread
import json
import sys

class Server():
    def __init__(self, host='127.0.0.1', port=54321):
        self.Clients = {}
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host, self.port = host, port
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        
    def listen(self):
        while True:
            client_socket, client_address = self.socket.accept()
            msg_id = client_socket.recv(1024).decode()
            client_id = json.loads(msg_id)
            self.Clients[client_id['Client ID']] = client_socket  
            print("Connection from: " + str(client_address))
            Thread(target = self.handle_new_client, args = (client_address, client_socket,)).start()
            
    def handle_new_client(self, client_address, client_socket):
        while True:
            message = client_socket.recv(1024).decode()
            msg_dict = json.loads(message)
            if msg_dict['Message'].strip() == 'exit system':
                del self.Clients[client_address]
                client_socket.close()
                break
            else: 
                receiver_id = msg_dict['To']
                receiver_socket = self.Clients[receiver_id]
                receiver_socket.send(message.encode())
    
server = Server()
server.listen()