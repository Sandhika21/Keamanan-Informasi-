import function

class Initiator():
    def __init__(self):
        self.e, self.d, self.n = function.PKA_key_pair()
        self.initiator_e, _, self.initiator_n = function.initiator_key_pair()
        self.responder_e, self.responder_n = function.responder_key_pair()