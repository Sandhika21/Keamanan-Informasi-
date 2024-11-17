import socket
from threading import Thread
import json
import sys

class Server():
    def __init__(self, host='127.0.0.1', port=12345):
        self.Clients = {}
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host, self.port = host, port
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        
    def listen(self):
        while True:
            client_socket, client_address = self.socket.accept()
            self.Clients[client_address] = client_socket  
            print("Connection from: " + str(client_address))
                      
            Thread(target = self.handle_new_client, args = (client_address, client_socket,)).start()
            
    def handle_new_client(self, client_address, client_socket):
        while True:
            message = self.receive_message(client_socket)
            msg_dict = json.loads(message)
            if msg_dict['Message'].strip() == 'exit system':
                del self.Clients[client_address]
                client_socket.close()
                break
            else: 
                receiver_address = msg_dict['To']
                receiver_socket = self.Clients[receiver_address]
                receiver_socket.sendall(message.encode())
    
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
            self.socket.close()
            sys.exit(1)
        return data.decode()
    
server = Server()
server.listen()