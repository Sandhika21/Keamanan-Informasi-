import function
from threading import Thread
import socket
import json
import time
import random
import sys

class Initiator():
    def __init__(self, IDA=None, des_key='aKiHDNaS', server_host='127.0.0.1', server_port=12345):
        self.des_key = des_key
        self.responder_session_key = None
        self.DES = function.DES_function(des_key)
        self.responder_DES = None
        self.e, self.d, self.n = function.initiator_key_pair()
        self.responder_e, self.responder_n = None, None
        self.PKA_e, _, self.PKA_n = function.PKA_key_pair()
        self.N1 = random.randint(1, 100)
        self.IDA = IDA
        self.isSuccess = False
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_host, self.server_port = server_host, server_port
        self.host, self.port = function.initiator_hp()
        self.responder_host, self.responder_port = function.responder_hp()
        self.PKA_host, self.PKA_port = function.PKA_hp()
        
    def connect_to_server(self):
        try:
            self.socket.bind((self.host, self.port))
            self.socket.connect((self.server_host, self.server_port))
            self.connection_handling()
            
            Thread(target=self.rcv_message, daemon=True).start()
            while True:
                content = input("Enter message : ")
                content_dict = json.dumps({
                    'MSG' : content
                })
                msg = 'sending'
                if content == 'exit system':
                    msg = 'exit system'
                encrypted_content = self.responder_DES.encrypt_message(content_dict)
                encrypted_message = self.create_message(msg, (self.responder_host, self.responder_port), encrypted_content)
                self.socket.sendall(encrypted_message.encode())
                if content == 'exit system':
                    self.socket.close()
                    break
                
                
        except Exception as e:
            print(f"Connection failed: {e}")
            self.socket.close()
            sys.exit(1)
            
    def rcv_message(self):
        while True:
            respond = self.receive_message()
            respond_dict = json.loads(respond)
            decode_content = self.DES.decrypt_message(respond_dict['Content'])
            content_dict = json.loads(decode_content)
            print(f"RECV: \n\t{content_dict['MSG']} | length: {len(content_dict)}")
            
    def receive_message(self):
        data = b''
        try:
            while True:
                packet = self.socket.recv(1024)
                if not packet:
                    break
                data += packet
        except Exception as e:
            print(f"Error receiving message: {e}")
            self.socket.close()
            sys.exit(1)
        return data.decode()
            
    def connection_handling(self):
        if not self.isSuccess:
            isHandshake = self.handshake()
            if not isHandshake:
                self.socket.close()
                sys.exit(1)
            self.isSuccess = True
        
        session_content = json.dumps({
            'des_key' : self.des_key
        })
        e_session_content = function.encrypt(session_content, self.responder_e, self.responder_n)
        session_msg = self.create_message('session key', (self.responder_host, self.responder_port), e_session_content)
        self.socket.sendall(session_msg.encode())
        responder_session_key = self.receive_message()
        session_respond = json.loads(responder_session_key)
        d_session_respond = function.encrypt(session_respond['Content'], self.d, self.n)
        session_content = json.loads(d_session_respond)
        self.responder_session_key = session_content['des_key']
        self.responder_DES = function.DES_function(self.responder_session_key)
        
        print("Session key has been distributed")
        
    def handshake(self):
        try:            
            request_message = json.dumps({
                'Message' : 'Request',
                'Time Stamp' : time.asctime(time.localtime(time.time())),
                'From' : 'Initiator',
                'To' : 'PKA'
            })
            
            request_message = self.create_message('Request', (self.PKA_host, self.PKA_port))
            self.socket.sendall(request_message.encode())
            respond_PKA = self.receive_message()
            PKA_respond = json.loads(respond_PKA)
            d_content_PKA = function.encrypt(PKA_respond['Content'], self.PKA_e, self.PKA_n)
            PKA_content = json.loads(d_content_PKA)
            
            
            self.responder_e, self.responder_n = PKA_content['Public Key']
            check_content = json.dumps({
                'myN' : self.N1,
                'ID' : self.IDA
            })
            e_check_content = function.encrypt(check_content, self.responder_e, self.responder_n)
            checking_msg = self.create_message('to Responder', (self.responder_host, self.responder_port), e_check_content) 
            self.socket.sendall(checking_msg.encode())
            check_responder = self.receive_message()            
            check_respond = json.loads(check_responder)
            d_check_content = function.encrypt(check_respond['Content'], self.d, self.n)
            check_content = json.loads(d_check_content)
            
            
            if check_content['yourN'] != self.N1:
                return False
            
            confirm_content = json.dumps({
                'yourN' : check_content['myN']
            })        
            e_confirm_content = function.encrypt(confirm_content, self.responder_e, self.responder_n)
            confirm_msg = self.create_message('confirm', (self.responder_host, self.responder_port), e_confirm_content)
            
            self.socket.sendall(confirm_msg.encode())
            
            self.isSuccess = True
            return True
        
        except Exception as e:
            print(f"Handshake error: {e}")
            return False
    
    def create_message(self, message, receiver, content=None):
        return json.dumps({
            'Message' : message,
            'Time Stamp' : time.asctime(time.localtime(time.time())),
            'From' : (self.host, self.port),
            'To' : receiver,
            'Content' : content
        })

init = Initiator(9)
init.connect_to_server()