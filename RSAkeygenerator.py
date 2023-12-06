import random
import math

class RSAKeyGenerator:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.p = self.q = self.n = self.fn = self.e = self.d = None
        self.generate_keys()

    def miller_rabin(self, n, k):
        if n in {2, 3}:
            return True

        if n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2

        for _ in range(k):
            a = random.randint(2, n - 2)
            x = pow(a, s, n)

            if x in {1, n - 1}:
                continue

            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False

        return True
    def generate_primes(self):
        n = self.get_random_odd_number()
        while not self.miller_rabin(n, 40):
            n = self.get_random_odd_number()
        return n

    def get_random_odd_number(self):
        n = random.getrandbits(self.key_size)
        return n | 1

    def extended_gcd(self, a, m):
        if math.gcd(a, m) != 1:
            return None

        u1, u2, u3 = 1, 0, a
        v1, v2, v3 = 0, 1, m
        while v3 != 0:
            q = u3 // v3
            v1, v2, v3, u1, u2, u3 = (
                u1 - q * v1,
                u2 - q * v2,
                u3 - q * v3,
                v1,
                v2,
                v3,
            )
        return u1 % m

    def generate_keys(self):
        self.generate_prime_pair()
        self.calculate_n_and_fn()
        self.calculate_public_key()
        self.calculate_private_key()

    def generate_prime_pair(self):
        while True:
            try:
                self.p = self.generate_primes()
                self.q = self.generate_primes()
                break
            except RecursionError:
                pass

    def calculate_n_and_fn(self):
        self.n = self.p * self.q
        self.fn = (self.p - 1) * (self.q - 1)

    def calculate_public_key(self):
        self.e = 0
        while math.gcd(self.fn, self.e) != 1:
            self.e = random.randrange(2, self.fn)

    def calculate_private_key(self):
        self.d = self.extended_gcd(self.e, self.fn)

    def get_private_key(self):
        return self.d, self.n

    def get_public_key(self):
        return self.e, self.n

    def rsa_encrypt(self, message, public_key):
        e, n = public_key
        cipher_text = [pow(ord(char), e, n) for char in message]
        return cipher_text

    def rsa_decrypt(self, cipher_text, private_key):
        d, n = private_key
        decrypted_text = ''.join([chr(pow(char, d, n)) for char in cipher_text])
        return decrypted_text
