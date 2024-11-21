import socket
import json
import function
import random

class Responder:
    def __init__(self, host='127.0.0.1', port=64654, pka_host='127.0.0.1', pka_port=7632):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.host, self.port = host, port
        self.pka_host, self.pka_port = pka_host, pka_port
        self.e, self.d, self.n = function.responder_key_pair()
        self.PKA_e, _, self.PKA_n = function.PKA_key_pair()
        self.N2 = random.randint(100, 10000)  # Generate N2
        self.des_key = None
        self.des = None
        print(f"Responder initialized with public key (e={self.e}, n={self.n}).")

    def connect_to_pka(self):
        print("Connecting to PKA...")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as pka_socket:
            pka_socket.connect((self.pka_host, self.pka_port))
            print(f"Connected to PKA at {self.pka_host}:{self.pka_port}.")
            
            request_message = json.dumps({
                "Message": "request key",
                "Client ID": "Initiator"
            })
            print(f"Requesting key for Initiator: {request_message}")
            pka_socket.sendall(request_message.encode())
            
            response = pka_socket.recv(1024).decode()
            response_data = json.loads(response)
            print(f"Response from PKA: {response_data}")
            
            if response_data['Message'] == 'key':
                decrypted_key = function.encrypt(response_data['Content'], self.d, self.n)
                print(f"Decrypted key from PKA: {decrypted_key}")
                key_data = json.loads(decrypted_key)
                self.PKA_e, self.PKA_n = key_data
            else:
                raise ValueError("Failed to retrieve key from PKA")

    def handshake(self, client_socket):
        print("Starting handshake with Initiator...")
        # Send N2 to Initiator
        print(f"Generated N2: {self.N2}")
        n2_message = json.dumps({
            "Message": "N2",
            "Content": self.N2
        })
        client_socket.sendall(n2_message.encode())
        print("Sent N2 to Initiator.")

        # Receive response for N2
        print("Waiting for response from Initiator...")
        response = client_socket.recv(1024).decode()
        print(f"Received response: {response}")
        response_data = json.loads(response)
        
        decrypted_n2 = int(function.encrypt(response_data['Content'], self.d, self.n))
        print(f"Decrypted N2 from Initiator: {decrypted_n2}")

        # Validate N2
        if decrypted_n2 != self.N2:
            print("N2 validation failed. Terminating connection.")
            raise ValueError("N2 mismatch! Handshake failed.")
        print("Handshake successful with N2 validation.")

    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Responder is listening on {self.host}:{self.port}...")

        while True:
            print("Waiting for a connection...")
            client_socket, client_address = self.socket.accept()
            print(f"Connection established with {client_address}.")
            try:
                self.handshake(client_socket)  # Perform handshake
                print("Handshake completed. Ready for DES key exchange.")
                # Continue with DES key exchange logic here
            except Exception as e:
                print(f"Error during handshake with {client_address}: {e}")
                client_socket.close()

responder = Responder()
responder.start()
