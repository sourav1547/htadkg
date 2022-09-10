# Implements hybrid between Feldman and Pedersen polynomial commitment. 

class PolyCommitHybrid:
    def __init__(self, g, h, field, multiexp):
        self.g, self.h = g, h
        self.ZR = field
        self.multiexp = multiexp

    def commit(self, phi, phi_hat=None):
        if phi_hat is None:
            return [self.g ** coeff for coeff in phi.coeffs]

        return [self.multiexp([self.g, self.h], [phi.coeffs[i], phi_hat.coeffs[i]]) for i in range(len(phi.coeffs))]

    def verify_eval(self, c, i, phi_at_i, phi_hat_at_i=None):
        powers = [self.ZR(i**j) for j in range(len(c))]
        lhs = self.multiexp(c, powers)
        if phi_hat_at_i is None:
            return lhs == self.g ** phi_at_i
        return lhs == self.multiexp([self.g, self.h],[phi_at_i, phi_hat_at_i])


    def create_witness(*args):
        return None

    def batch_create_witness(self, c, phi, n, *args):
        return [None] * n
    
    def double_batch_create_witness(self, cs, phis, n, *args):
        return [[None] * len(phis)] * n
    
    def batch_verify_eval(self, cs, i, phis_at_i, *args):
        for j in range(len(cs)):
            if not self.verify_eval(cs[j], i, phis_at_i[j]):
                return False
        return True
    
    def preprocess(self, level=8):
        self.g.preprocess(level)

    #homomorphically add commitments
    def commit_add(self, a, b):
        if len(a) > len(b):
            longer = a
            shorter = b
        else:
            longer = b
            shorter = a
        #the **1 is necessary to create a new copy and avoid dumb memory bugs
        out = [entry ** 1 for entry in longer]
        for i in range(len(shorter)):
            out[i] *=  shorter[i]
        return out
    
    def commit_sub(self, a, b):
        if len(a) > len(b):
            longer = a
            shorter = [entry**(-1) for entry in b]
        else:
            longer = [entry**(-1) for entry in b]
            shorter = a
        out = [entry ** 1 for entry in longer]
        for i in range(len(shorter)):
            out[i] *=  shorter[i]
        return out

    def get_secret_commit(self, c):
        return c[0]