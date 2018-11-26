# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import division

"""
LELEC2770 : Privacy Enhancing Technologies

Exercice Session : Secure 2-party computation

Oblivious Transfer
"""

from Crypto.Random import random

from elgamal import elgamal_param_gen
from aes import AES_key


class Sender:
    """Oblblivious transfer sender for AES keys

    :param msg_0: Message 0
    :param msg_1: Message 1
    :type msg_0: AES_key
    :type msg_1: AES_key
    """

    def __init__(self, msg_0, msg_1):
        assert isinstance(msg_0, AES_key)
        assert isinstance(msg_1, AES_key)
        self.m_0 = msg_0  # must be aes key
        self.m_1 = msg_1  # must be aes key

    def response(self, c, pk):
        """Response to a challenge sent by the receiver

        :param c: Encrypted challenge
        :param pk: Encryption public key
        :type c: ElgamalCiphertext
        :type pk: ElgamalPublicKey
        :return: Encrypted responses e_0, e_1
        :rtype: (ElgamalCiphertext, ElgamalCiphertext)
        """
        # <To be done by students>

        r_0 = pk.random()
        r_1 = pk.random()

        enc_1 = pk.encrypt(1)

        e_0 = ((enc_1 - c) * self.m_0.as_int()) + (r_0 * c)
        e_1 = (c * self.m_1.as_int()) + (r_1 * (enc_1 - c))

        # </To be done by students>

        return e_0, e_1


class Receiver:
    """Oblblivious transfer receiver for AES keys

    Attributes:
    * pk: Public key
    * sk: Secret key
    """

    def __init__(self):
        self.pk, self.sk = elgamal_param_gen()

    def challenge(self, b):
        """Generate an OT challenge

        :param b: Message to receive (0 or 1)
        :type b: int
        :return: OT challenge
        :rtype: ElgamalCiphertext
        """
        # <To be done by students>

        return self.pk.encrypt(b)

        # </To be done by students>

    def decrypt_response(self, e_0, e_1, b):
        """Decrypt response received from Sender

        :param e_0: Response part 0
        :param e_1: Response part 1
        :type e_0: ElgamalCiphertext
        :type e_1: ElgamalCiphertext
        :return: Transferred message
        :rtype: AES_key
        """
        # <To be done by students>

        if b == 0:
            m = self.sk.decrypt(e_0)
        elif b == 1:
            m = self.sk.decrypt(e_1)

        # </To be done by students>
        key = AES_key.from_int(m)
        return key


def test_OT():
    b = random.getrandbits(1)
    Bob = Receiver()

    k0 = AES_key.gen_random()
    k1 = AES_key.gen_random()
    Alice = Sender(k0, k1)

    c = Bob.challenge(b)
    pk = Bob.pk

    e0, e1 = Alice.response(c, pk)
    k = Bob.decrypt_response(e0, e1, b)

    assert (k0, k1)[b] == k
    print(k0.as_int(), k1.as_int(), b, k.as_int())


if __name__ == "__main__":
    test_OT()
