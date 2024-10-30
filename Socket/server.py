import socket

def asciiToBin(messages):
    size = divmod(len(messages), 8)
    msg = []
    for i in range(size[0]):
        msg.append(''.join(bin(ord(i))[2:].zfill(8) for i in messages[i*8 : (i+1)*8]))
    if size[1] > 0:
        msg.append(''.join(bin(ord(i))[2:].zfill(8) for i in messages[size[0]*8 : size[0]*8 + size[1]]).ljust(64, '0'))
    return msg

def binToAscii(messages):
    return ''.join(chr(int(message[i*8 : (i+1)*8], 2)) for message in messages for i in range(8)).rstrip('\x00')
    
def permutation(shuffle_bits, binary):
    return ''.join(binary[bit - 1] for bit in shuffle_bits)


class Key():
    def __init__(self, key):
        self.key = permutation(self.PC1(), key)
        self.keys = []
        self.exc = [1, 2, 9, 16]
        
    def key_generator(self):
        for i in range(1, 17):
            shift = 2
            if i in self.exc:
                shift = 1
            self.key = self.key[shift:28] + self.key[:shift] + self.key[shift+28:] + self.key[28 : shift+28]
            sub_key = permutation(self.PC2(), self.key)
            self.keys.append(sub_key)
        return self.keys
    
    def PC1(self): #64 bit => 56 bit
        return [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,
                59,51,43,35,27,19,11,3,60,52,44,36,63,55,
                47,39,31,23,15,7,62,54,46,38,30,22,14,6,
                61,53,45,37,29,21,13,5,28,20,12,4]
    def PC2(self): #56 bit => 48 bit
        return [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,
                26,8,16,7,27,20,13,2,41,52,31,37,47,55,
                30,40,51,45,33,48,44,49,39,56,34,53,46,
                42,50,36,29,32]
        
class Message():
    def __init__(self, keys):
        self.keys = keys
                
    def XOR(self, bin1, bin2):
        binary = ""
        for i in range(len(bin1)):
            if bin1[i] == bin2[i]:
                binary += "0"
            else:
                binary += "1"
        return binary
    
    def substitution(self, xor_bits):
        substituted_bits = ""
        for i in range(8):
            row = int((xor_bits[i*6] + xor_bits[i*6+5]), 2)
            column = int((xor_bits[i*6+1] + xor_bits[i*6+2] + xor_bits[i*6+3] + xor_bits[i*6+4]), 2)
            substituted_bits += bin(self.Substitution_Boxes()[i][row][column])[2:].zfill(4)
        return substituted_bits
    
    def encrypt_message(self, messages):
        encrypted_message = []
        messages = asciiToBin(messages)
        for message in messages:
            bin_message = self.encryption(message, self.keys)
            encrypted_message.append(bin_message)
        return binToAscii(encrypted_message)
    
    def decrypt_message(self, messages):
        decrypted_message = []
        messages = asciiToBin(messages)
        for message in messages:
            bin_message = self.encryption(message, self.keys[::-1])
            decrypted_message.append(bin_message)
        return binToAscii(decrypted_message)
        
    
    def encryption(self, message, key):
        permuted_msg = permutation(self.initial_permutation(), message)
        left = permuted_msg[:32]
        right = permuted_msg[32:]
        
        for i in range(16):
            exp_bits = permutation(self.Expansion_Permutation(), right)
            xor_bits = self.XOR(key[i], exp_bits)
            substituted_bits = self.substitution(xor_bits)
            f_per_bits = permutation(self.Permutation_Function(), substituted_bits)
            
            left, right = right, self.XOR(left, f_per_bits)
            
        return permutation(self.final_permutation(), right + left)
    
    def initial_permutation(self): #64 bit
        ip = []
        for i in range(1, 9):
            for j in range(1, 9):
                last = (2*i) % 9
                ip.append((8-j)*8 + last)
        return ip

    def Expansion_Permutation(self): #32 bit => 48 bit
        return [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
    
    def Substitution_Boxes(self):
        return [
        [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7], [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8], [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0], [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
        [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10], [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5], [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15], [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
        [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8], [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1], [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7], [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
        [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15], [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9], [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4], [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
        [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9], [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6], [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14], [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
        [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11], [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8], [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6], [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
        [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1], [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6], [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2], [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
        [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7], [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2], [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8], [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
    ]
        
    def Permutation_Function(self): #32 bit
        return [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
        
    def final_permutation(self): #64 bit
        inv_ip = []
        for i in range(0, 8):
            for j in range(1, 9):
                isEven = j%2
                interval = (j//2) + (j%2)
                inv_ip.append(((4*isEven + interval)*8) - i)
        return inv_ip

def main():
    key = "t2Socket"
    msg = Message(Key(key=asciiToBin(key)[0]).key_generator())

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen(1)
    print("Server is listening on port 65432")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connected to client: {client_address}")

        while True:
            received_data = client_socket.recv(1024).decode()
            if not received_data:
                break

            decrypted_message = msg.decrypt_message(received_data)
            print(f"RECV: \n\tCipherText : {received_data} \n\tPlainText : {decrypted_message} | length: {len(decrypted_message)}")

            if decrypted_message == 'exit':
                print("Connection closed by client.")
                client_socket.close()
                break

            response = input("SEND: ")
            encrypted_response = msg.encrypt_message(response)
            client_socket.send(encrypted_response.encode())

        client_socket.close()

if __name__ == '__main__':
    main()
