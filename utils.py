import os
import random

def is_prime(n, k=12):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False
    
    s = 0
    d = n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        
        composite = True
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                composite = False
                break
        if composite:
            return False
    return True

def generate_prime_number(bits=512):
    while True:        
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_prime(candidate):
            return candidate

def find_primitive_root(p):
    if p == 2:
        return 1
    
    while True:
        g = random.randint(2, p - 1)
    
        if pow(g, (p - 1) // 2, p) != 1:
            return g

def extended_gcd(a, b):
    
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(a, m):
    
    gcd, x, _ = extended_gcd(a, m)
    if gcd != 1:
        raise ValueError("Modular inverse tidak ada (tidak coprime).")
    return (x % m + m) % m


class DiffieHellman:
    def __init__(self, p=None, g=None, bits=512):
        
        self.bits = bits
        self.p = p if p else generate_prime_number(bits)
        self.g = g if g else find_primitive_root(self.p)
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        
        self.private_key = random.randint(2, self.p - 2)
        self.public_key = pow(self.g, self.private_key, self.p)
        return self.public_key

    def compute_shared_secret(self, other_public_key):
        
        if not self.private_key:
            raise ValueError("Generate kunci privat terlebih dahulu!")
        shared_secret = pow(other_public_key, self.private_key, self.p)
        return shared_secret


class ElGamal:
    def __init__(self, p=None, g=None, bits=512):
        """
        Inisialisasi sistem ElGamal dengan p dan g.
        """
        self.bits = bits
        self.p = p if p else generate_prime_number(bits)
        self.g = g if g else find_primitive_root(self.p)

    def generate_keypair(self):
        
        x = random.randint(2, self.p - 2)
        y = pow(self.g, x, self.p)
        public_key = (self.p, self.g, y)
        private_key = x
        return public_key, private_key

    @staticmethod
    def encrypt_number(m, public_key):
        
        p, g, y = public_key
        if m >= p:
            raise ValueError("Pesan m terlalu besar! Harus < p.")
        
        
        k = random.randint(2, p - 2)
        c1 = pow(g, k, p)
                
        s = pow(y, k, p)
        c2 = (m * s) % p
        return (c1, c2)

    @staticmethod
    def decrypt_number(ciphertext, private_key, p):
        
        c1, c2 = ciphertext
        
        s = pow(c1, private_key, p)
        
        s_inv = mod_inverse(s, p)
        
        m = (c2 * s_inv) % p
        return m


    @classmethod
    def encrypt_text(cls, text, public_key):
        
        p, _, _ = public_key
        ciphertexts = []
        for char in text:
            m = ord(char)
            ciphertexts.append(cls.encrypt_number(m, public_key))
        return ciphertexts

    @classmethod
    def decrypt_text(cls, ciphertexts, private_key, p):
        
        decrypted_chars = []
        for cipher in ciphertexts:
            m = cls.decrypt_number(cipher, private_key, p)
            decrypted_chars.append(chr(m))
        return "".join(decrypted_chars)

    @staticmethod
    def multiply_homomorphic(cipher1, cipher2, p):
        
        c1_a, c2_a = cipher1
        c1_b, c2_b = cipher2
        
        c1_res = (c1_a * c1_b) % p
        c2_res = (c2_a * c2_b) % p
        return (c1_res, c2_res)



