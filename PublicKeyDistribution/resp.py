import function
from threading import Thread
import socket
import json
import time
import random
import sys

class Responder():
    def __init__(self, des_key='sAndhIkA'):
        self.DES = function.DES_function(des_key)
        self.des_key = des_key        
        self.e, self.d, self.n = function.responder_key_pair()
        self.ID_dev = None
        self.N2 = random.randint(100, 10000)
        self.isSuccess = False
        
        self.initiator_session_key = None
        self.initiator_DES = None
        self.initiator_e, self.initiator_n = None, None
        
        self.PKA_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.PKA_host, self.PKA_port = '127.0.0.1', 2345
        self.PKA_e, _, self.PKA_n = function.PKA_key_pair()
        
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_host, self.server_port = '127.0.0.1', 54321
        
        
        
    def connect_to_server(self):
        try:
            client_id = json.dumps({
                'Message' : 'register ID',
                'Client ID' : 'Responder'
            })
            self.server_socket.connect((self.server_host, self.server_port))
            self.server_socket.send(client_id.encode())
            
            self.PKA_socket.connect((self.PKA_host, self.PKA_port))
            self.PKA_socket.send(client_id.encode())
            
            self.connection_handling()
            
            if self.isSuccess:
                Thread(target=self.rcv_message, daemon=True).start()
                while True:
                    content = input()
                    content_dict = json.dumps({
                        'MSG' : content
                    })
                    msg = 'sending'
                    if content == 'exit system':
                        msg = 'exit system'
                    encrypted_content = self.initiator_DES.encrypt_message(content_dict)
                    encrypted_message = self.create_message(msg, 'Initiator', encrypted_content)
                    self.server_socket.send(encrypted_message.encode())
                    if content == 'exit system':
                        self.server_socket.close()
                        break
                
                
        except Exception as e:
            print(f"Connection failed: {e}")
            self.server_socket.close()
            sys.exit(1)
            
    def rcv_message(self):
        while True:
            respond = self.server_socket.recv(1024).decode()
            respond_dict = json.loads(respond)
            decode_content = self.DES.decrypt_message(respond_dict['Content'])
            content_dict = json.loads(decode_content)
            print(f"RECV: \n\t{content_dict['MSG']} | length: {len(content_dict['MSG'])}")
            
    def receive_message_server(self):
        data = b''
        try:
            while True:
                packet = self.server_socket.recv(1024)
                if not packet:
                    break
                data += packet
        except Exception as e:
            print(f"Error receiving message: {e}")
            self.server_socket.close()
            sys.exit(1)
        return data.decode()
    
    def receive_message_pka(self):
        data = b''
        try:
            while True:
                packet = self.PKA_socket.recv(1024)
                if not packet:
                    break
                data += packet
        except Exception as e:
            print(f"Error receiving message: {e}")
            self.PKA_socket.close()
            sys.exit(1)
        return data.decode()
            
    def connection_handling(self):
        if not self.isSuccess:
            isHandshake = self.handshake()
            if not isHandshake:
                self.server_socket.close()
                sys.exit(1)
            self.isSuccess = True
        
        
        initiator_session_key = self.server_socket.recv(1024).decode() 
        session_respond = json.loads(initiator_session_key)
        d_session_respond = function.encrypt(session_respond['Content'], self.d, self.n)
        session_content = json.loads(d_session_respond)
        self.initiator_session_key = session_content['des_key']
        self.initiator_DES = function.DES_function(self.initiator_session_key)
        
        session_content = json.dumps({
            'des_key' : self.des_key
        })
        e_session_content = function.encrypt(session_content, self.initiator_e, self.initiator_n)
        session_msg = self.create_message('session key', 'Initiator', e_session_content)
        self.server_socket.send(session_msg.encode())
        
        print("Session key has been distributed")
        
    def handshake(self):
        try:
            check_initiator = self.server_socket.recv(1024).decode()           
            check_respond = json.loads(check_initiator)
            d_check_content = function.encrypt(check_respond['Content'], self.d, self.n)
            check_content = json.loads(d_check_content)
            self.ID_dev = check_content['ID']

            request_message = json.dumps({
                'Message' : 'request key',
                'Time Stamp' : time.asctime(time.localtime(time.time())),
                'From' : 'Responder',
                'Client ID' : 'Initiator'
            })
            self.PKA_socket.send(request_message.encode())
            respond_PKA = self.PKA_socket.recv(1024).decode()
            PKA_respond = json.loads(respond_PKA)
            d_content_PKA = function.encrypt(PKA_respond['Content'], self.PKA_e, self.PKA_n)
            PKA_content = json.loads(d_content_PKA)
            self.initiator_e, _, self.initiator_n = PKA_content['Public Key']
            
            respond_content = json.dumps({
                'myN' : self.N2,
                'yourN' : check_content['myN'],
            })
            e_respond_content = function.encrypt(respond_content, self.initiator_e, self.initiator_n)
            respond_msg = self.create_message('to Responder', 'Initiator', e_respond_content) 
            self.server_socket.send(respond_msg.encode())
            
            confirm_initiator = self.server_socket.recv(1024).decode()
            confirm_respond = json.loads(confirm_initiator)
            d_confirm_content = function.encrypt(confirm_respond['Content'], self.d, self.n)
            confirm_content = json.loads(d_confirm_content)          
            
            if confirm_content['yourN'] != self.N2:
                return False
            
            self.isSuccess = True
            return True
        
        except Exception as e:
            print(f"Handshake error: {e}")
            return False
    
    def create_message(self, message, receiver, content=None):
        return json.dumps({
            'Message' : message,
            'Time Stamp' : time.asctime(time.localtime(time.time())),
            'From' : 'Responder',
            'To' : receiver,
            'Content' : content
        })

resp = Responder()
resp.connect_to_server()