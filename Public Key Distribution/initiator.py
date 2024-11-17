import function
from threading import Thread
import socket
import json
import time
import random
import sys

class Initiator():
    def __init__(self, IDA=None, des_key='aKiHDNaS'):
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
        self.host, self.port = function.initiator_hp()
        self.responder_host, self.responder_port = function.responder_hp()
        self.PKA_host, self.PKA_port = function.PKA_hp()
        
    def connect_to_server(self):
        try:
            self.socket.connect((self.host, self.port))
            self.connection_handling()
            
            Thread(target=self.rcv_message, daemon=True).start()
            while True:
                message = input("Enter message : ")
                encrypted_message = self.responder_DES.encrypt_message(message)
                self.socket.sendall(encrypted_message.encode())

        except Exception as e:
            print(f"Connection failed: {e}")
            self.socket.close()
            sys.exit(1)
            
    def rcv_message(self):
        while True:
            respond = self.receive_message()
            decryted_respond = self.DES.decrypt_message(respond)
            print(f"RECV: \n\tCipherText : {respond} \n\tPlainText : {decryted_respond} | length: {len(decryted_respond)}")
            
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
        
        session_content = {
            'des_key' : self.des_key
        }
        session_msg = self.create_message('session key', (self.responder_host, self.responder_port), session_content)
        e_session_msg = function.encrypt(session_msg, self.responder_e, self.responder_n)
        self.socket.sendall(e_session_msg.encode())
        responder_session_key = self.receive_message()
        d_responder_session_key = function.encrypt(responder_session_key, self.d, self.n)
        session_respond = json.loads(d_responder_session_key)
        session_content = json.loads(session_respond['Content'])
        self.responder_session_key = session_content['des_key']
        self.responder_DES = function.DES_function(self.responder_session_key)
        
        print("Session key has been distributed")
        
    def handshake(self):
        try:            
            request_message = self.create_message('Request', (self.PKA_host, self.PKA_port))
            self.socket.sendall(request_message.encode())
            respond_PKA = self.receive_message()
            d_respond_PKA = function.encrypt(respond_PKA, self.PKA_e, self.PKA_n)
            PKA_respond = json.loads(d_respond_PKA)
            PKA_content = json.loads(PKA_respond['Content'])
            
            self.responder_e, self.responder_n = PKA_content['Public Key']
            check_content = json.dumps({
                'myN' : self.N1,
                'ID' : self.IDA
            })
            checking_msg = self.create_message('to Responder', (self.responder_host, self.responder_port), check_content)
            e_checking_msg = function.encrypt(checking_msg, self.responder_e, self.responder_n)
            self.socket.sendall(e_checking_msg.encode())
            check_responder = self.receive_message()
            d_check_responder = function.encrypt(check_responder, self.d, self.n)
            check_respond = json.loads(d_check_responder)
            check_content = json.loads(check_respond['Content'])
            
            if check_content['yourN'] != self.N1:
                return False
            
            confirm_content = json.dumps({
                'yourN' : check_content['myN']
            })        
            confirm_msg = self.create_message('confirm', (self.responder_host, self.responder_port), confirm_content)
            e_confirm_msg = function.encrypt(confirm_msg, self.responder_e, self.responder_n)
            self.socket.sendall(e_confirm_msg.encode())
            
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