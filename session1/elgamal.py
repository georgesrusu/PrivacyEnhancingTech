# -*- coding: utf-8 -*-
"""
LELEC2770 : Privacy Enhancing Technologies

El Gamal encryption library
"""

import gmpy
from Crypto.Random.random import randint
from Crypto.Hash import SHA256


def elgamal_param_gen():
    """Generate an El Gamal keypair

    :rtype: (ElgamalPublicKey, ElgamalSecretKey)
    """
    p = 4
    while not gmpy.is_prime(p):
        r = randint(0, 2 ** 64)
        q = gmpy.next_prime(2 ** 64 + r)
        p = 2 * q + 1

    g_prime = randint(1, int(p - 1))
    g = pow(g_prime, 2, p)  # generator of the group
    assert pow(g, q, p) == 1
    G = g, p, q
    x = randint(1, int(q - 1))  # secret key
    y = pow(g, x, p)  # public key
    pk = ElgamalPublicKey(G, y)
    sk = ElgamalSecretKey(G, x)
    return pk, sk


class ElgamalPublicKey:
    """El Gamal public key"""

    def __init__(self, G, y):
        self.G = G
        self.y = y

    def random(self):
        """Generate a random group element."""
        p = self.G[1]
        return randint(1, int(p))

    def encrypt(self, m, r=None):
        """Encrypt a message.

        :param m: plaintext
        :param r: optionnal random group element to use for encryption
        :type m: int
        :type r: int or None
        """
        if r == None:
            r = self.random()
        # Message length must be less than 20 bits. @students: Why is it so ?
        assert len(format(m, "b")) <= 20
        g = self.G[0]
        p = self.G[1]

        if r < 0:
            r = p - r
        c1 = pow(g, r, p)
        c2 = (pow(g, m, p) * pow(self.y, r, p)) % p

        return ElgamalCiphertext(p, c1, c2)

    def verifiability_proof(self, c, m, r, s=None, u=None, t=None):
        """ This ZK proof ensures that c is a el_gamal on m = 0 or 1
        s,u,t are the randomness used in the proof (optional)
        """
        # notations
        p = self.G[1]

        assert m == 0 or m == 1  # the proof works only if m = 0 or 1

        if s == None:
            s = self.random()
        if u == None:
            u = self.random()
        if t == None:
            t = self.random()

        if m == 0:
            # commitment
            u1 = u
            t1 = t
            w0 = self.encrypt(0, s)
            w1 = self.encrypt(t1, u1 - t1 * r)
            # challenge
            t0 = self._hashf([self.G, self.y, c, w0, w1]) - t1
            # response
            u0 = (s + r * t0) % p
        else:
            # m == 1
            # commitment
            u0 = u
            t0 = t
            w0 = self.encrypt(-t0, u0 - t0 * r)
            w1 = self.encrypt(0, s)
            # challenge
            t1 = self._hashf([self.G, self.y, c, w0, w1]) - t0
            # response
            u1 = (s + r * t1) % p
        return [u0, u1, t0, t1]

    def verifiability_proof_check(self, c, proof):
        """ Return True if the ZKP proof is correct with respect to c
        meaning that c is a el_gamal on either 0 or 1
        """
        # notations
        c1 = c.c1
        c2 = c.c2
        p = self.G[1]
        g = self.G[0]
        y = self.y

        u0, u1, t0, t1 = proof

        w0_1 = u0 * g - t0 * c1
        w0_2 = u0 * y - t0 * c2
        w0 = ElgamalCiphertext(p, w0_1, w0_2)

        w1_1 = u1 * g - t1 * c1
        w1_2 = u1 * y - t1 * c2 + t1 * g
        w1 = ElgamalCiphertext(p, w1_1, w1_2)

        return (t0 + t1) % p == self._hashf([self.G, self.y, c, w0, w1])

    def _hashf(self, L):
        p = self.G[1]
        hash_f = SHA256.new()
        for obj in L:
            if type(obj) is tuple:
                for i in obj:
                    hash_f.update(str(i))
            elif obj is ElgamalCiphertext:
                hash_f.update(str(obj.c1))
                hash_f.update(str(obj.c2))
            else:
                hash_f.update(str(obj))
        d = hash_f.digest()
        return int(d.encode("hex"), 16) % p


def dLog(p, g, g_m):
    """Compute the discrete log of g_m with basis g, modulo p"""
    # TODO: optimize this
    a = 1
    i = 0
    while i < 2 ** 20:
        if a == g_m:
            return i
        else:
            a = a * g % p
            i += 1
    return None  # no DLog < 2**20 found


class ElgamalSecretKey:
    """El Gamal secret key."""

    def __init__(self, G, x):
        self.G = G
        self.x = x

    def decrypt(self, c):
        """Decrypt ciphertext c.

        :returns: plaintext
        :rtype: int
        """
        assert isinstance(c, ElgamalCiphertext)
        g = self.G[0]
        p = self.G[1]
        c1 = c.c1
        c2 = c.c2
        c1_prime = pow(c1, self.x, p)
        g_m = gmpy.divm(c2, c1_prime, p)
        m = dLog(p, g, g_m)
        return m


class ElgamalCiphertext:
    """El Gamal ciphertext.

    Thanks to group homomorphism, operations over plaintexts can be implemented
    in the ciphertext domain.
    For two ciphertexts ca, cb and an integer a,
    * ca+cb corresponds to plaintext addition (hence ciphertext multiplication)
    * a*ca corresponds to plaintext multiplication (hence ciphertext
    exponentiation)

    Available operations: addition, subtraction, negation, multiplication.
    """

    def __init__(self, p, c1, c2):
        self.p = p
        self.c1 = c1
        self.c2 = c2

    def __add__(self, other):
        return ElgamalCiphertext(self.p, self.c1 * other.c1, self.c2 * other.c2)

    def __neg__(self):
        inv_c1 = gmpy.invert(self.c1, self.p)
        inv_c2 = gmpy.invert(self.c2, self.p)
        return ElgamalCiphertext(self.p, inv_c1, inv_c2)

    def __sub__(self, other):
        return self.__add__(other.__neg__())

    def __radd__(self, other):
        return self.__add__(other)

    def __mul__(self, alpha):
        return ElgamalCiphertext(
            self.p, pow(self.c1, alpha, self.p), pow(self.c2, alpha, self.p)
        )

    def __rmul__(self, other):
        return self.__mul__(other)
