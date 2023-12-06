import hashlib
import os
import base64
from math import ceil

from RSAkeygenerator import RSAKeyGenerator


class RSASignatureGenerator:
    def __init__(self, public_key, private_key, label=b''):
        self.public_key = public_key
        self.private_key = private_key
        self.label = label

    def sha3_224(self, m):
        sha3 = hashlib.sha3_224()
        sha3.update(m)
        return sha3.digest()

    def mgf1(self, seed, mlen):
        t = b''
        hlen = 28

        for c in range(ceil(mlen / hlen)):
            c_bytes = c.to_bytes(4, byteorder='big')
            t += self.sha3_224(seed + c_bytes)

        return t[:mlen]

    def codifica_oaep(self, m, k, label=b''):
        mlen = len(m)
        lhash = self.sha3_224(label)
        hlen = len(lhash)

        ps_len = k - mlen - 2 * hlen - 2
        ps = b'\x00' * ps_len

        db = lhash + ps + b'\x01' + m

        seed = os.urandom(hlen)
        db_mask = self.mgf1(seed, k - hlen - 1)
        masked_db = self.xor_bloco(db, db_mask)

        seed_mask = self.mgf1(masked_db, hlen)
        masked_seed = self.xor_bloco(seed, seed_mask)

        return b'\x00' + masked_seed + masked_db

    def xor_bloco(self, a, b):
        return bytes(x ^ y for x, y in zip(a, b))

    def cifra_raw(self, mensagem, chave_publica):
        k = (chave_publica[1].bit_length() + 7) // 8
        c = self.cifra(int.from_bytes(mensagem, byteorder='big'), chave_publica)
        return c.to_bytes(length=k, byteorder='big')

    def cifra(self, mensagem, chave_publica):
        e, n = chave_publica
        return pow(mensagem, e, n)

    def assina_mensagem(self, mensagem):
        mensagem_bytes = mensagem.encode('utf-8')
        resultado_sha = self.sha3_224(mensagem_bytes)

        mensagem_hash = base64.encodebytes(resultado_sha).strip()
        k = (self.public_key[1].bit_length() + 7) // 8

        cifrado_oaep = self.codifica_oaep(mensagem_hash, k, self.label)
        c = self.cifra_raw(cifrado_oaep, self.private_key)

        return base64.encodebytes(c).strip()


