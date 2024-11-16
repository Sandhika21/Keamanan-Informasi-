import function

class Initiator():
    def __init__(self):
        self.e, self.d, self.n = function.initiator_key_pair()
        self.PKA_e, _, self.PKA_n = function.PKA_key_pair()
        
    

