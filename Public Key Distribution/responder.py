import function

class Responder():
    def __init__(self, des_key):
        self.DES = function.DES_function(des_key)
        self.e, self.d, self.n = function.responder_key_pair()
        self.PKA_e, _, self.PKA_n = function.PKA_key_pair()
        
    

