from pypairing import ZR as blsZR, G1 as blsG1
from pypairing import Curve25519ZR as ZR

class Serial:
    def __init__(self, G1):
        self.G1 = G1
        self.f_size = 32
        if G1 is blsG1:
            self.ZR = blsZR
            self.g_size = 48
        else:
            self.ZR = ZR
            self.g_size = 32


    def serialize_g(self, g):
        return g.__getstate__()

    def deserialize_g(self, data):
        g = self.G1()
        g.__setstate__(data)
        return g

    def deserialize_gs(self, data):
        n = len(data)//self.g_size
        gs = [None for _ in range(n)]
        for i in range(n):            
            g = self.G1()
            g.__setstate__(data[i*self.g_size:(i+1)*self.g_size])
            gs[i] = g
        return gs

    def serialize_gs(self, g_list):    
        n = len(g_list)
        data = bytearray()
        for i in range(n):
            g = g_list[i]
            data.extend(g.__getstate__())
        return data

    def serialize_f(self, f):
        return f.__getstate__()

    def deserialize_f(self, data):
        f = self.ZR()
        f.__setstate__(data)
        return f

    def serialize_fs(self, f_list):    
        n = len(f_list)
        data = bytearray()
        for i in range(n):
            f = f_list[i]
            data.extend(f.__getstate__())
        return data
    
    def deserialize_fs(self, data):    
        n = len(data)//self.f_size
        fs = [None for _ in range(n)]
        for i in range(n):            
            f = self.ZR()
            f.__setstate__(data[i*self.f_size:(i+1)*self.f_size])
            fs[i] = f
        return fs


