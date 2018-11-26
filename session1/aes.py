# -*- coding: utf-8 -*-
"""
LELEC2770 : Privacy Enhancing Technologies

AES key representation library
"""

import six
from Crypto.Cipher import AES
import Crypto.Random.random as rd
import Crypto.Util.number

AES_KEY_LEN_BYTES = 16
AES_BLOCK_LEN_BYTES = 16

class AES_key:
    """AES Key with multiple representations

    The supported formats are:

    - bytes: byte string (bytes type)
    - int: integer (int/long)
    - bin_str: string of bits '0'/'1'
    - bin: list of bits [0/1]
    - hex: string of hex digits (lowercase)

    The conversion between sequence and integer representations is in MSB order.
    """
    def __init__(self, rep_bytes):
        self.key = bytes(rep_bytes)

    @classmethod
    def gen_random(cls, nbr_zero=108):
        """Generate a random AES key.

        :param nbr_zero: number of leading bits at 0 in the key
        :type nbr_zero: int
        :return: AES key
        :rtype: AES_key
        """
        # @students: We use (by default) keys with 108 leading zeros, which
        # gives an effective key length of 20 bits.
        # Is it secure ? Could we increase it (e.g. to 128) bits
        rep_bin = [0] * nbr_zero
        rep_bin += [rd.randrange(2) for i in range(8 * AES_KEY_LEN_BYTES - nbr_zero)]
        return cls.from_bin(rep_bin)

    @classmethod
    def from_int(cls, rep_int):
        """Create an AES_key from its integer value.

        :type rep_int: int
        :rtype: AES_key
        """
        return cls(Crypto.Util.number.long_to_bytes(rep_int, AES_KEY_LEN_BYTES))

    @classmethod
    def from_bin_str(cls, rep_bin):
        """Create an AES_key from its binary string representation.

        :type rep_bin: str of "0" and "1" characters (of length 128)
        :rtype: AES_key
        """
        rep_byt = bytearray(
            int(rep_bin[8 * i : 8 * (i + 1)], 2) for i in range(AES_KEY_LEN_BYTES)
        )
        return cls(rep_byt)

    @classmethod
    def from_bin(cls, rep_bin):
        """Create an AES_key from its binary representation.

        :type rep_bin: list of 0 and 1 (of length 128)
        :rtype: AES_key
        """
        return cls.from_bin_str("".join(str(bit) for bit in rep_bin))

    @classmethod
    def from_hex(cls, rep_hex):
        """Create an AES_key from its hexadecimal string representation.

        :type rep_hex: str of hexadecimal digits (of length 32)
        :rtype: AES_key
        """
        rep_byt = bytearray(
            int(rep_hex[2 * i : 2 * (i + 1)], 16) for i in range(AES_KEY_LEN_BYTES)
        )
        return cls(rep_byt)

    @classmethod
    def from_bytes(cls, rep_bytes):
        """Create an AES_key from its bytes representation.

        :type rep_bytes: bytes object (of length 16)
        :rtype: AES_key
        """
        return cls(rep_bytes)

    def as_int(self):
        """Return the representation of the key as an integer.

        :rtype: int
        """
        return Crypto.Util.number.bytes_to_long(self.key)

    def as_bin_str(self):
        """Return the representation of the key as a binary string

        :rtype: str of 128 "0" and "1"
        """
        return "".join(format(b, "0>8b") for b in six.iterbytes(self.key))

    def as_bin(self):
        """Return the representation of the key as a binary list

        :rtype: list of 128 0 and 1
        """
        return [int(bit) for bit in self.as_bin_str()]

    def as_hex(self):
        """Return the representation of the key as an hexadecimal string

        :rtype: string of 32 hexadecimal digits
        """
        return "".join(format(b, "0>2x") for b in six.iterbytes(self.key))

    def as_bytes(self):
        """Return the representation of the key as byte string

        :rtype: bytes object of length 16
        """
        return self.key

    def encrypt(self, m):
        """Encrypt a message using the key

        :param m: Message to encrypt
        :type m: bytes object (of length multiple of 16) or int
        :return: Encrypted message
        :rtype: bytes object
        """
        AES_obj = AES.new(self.key, 1) # added 2nd arg 1
        if isinstance(m, six.integer_types):
            # convert m to bytestring
            m = Crypto.Util.number.long_to_bytes(m, AES_BLOCK_LEN_BYTES)
        return AES_obj.encrypt(m)

    def decrypt(self, c):
        """Decrypt a message using the key

        :param c: Message to decrypt
        :type c: bytes object whose length is multiple of 16
        :return: Decrypted message
        :rtype: bytes object
        """
        AES_obj = AES.new(self.key, 1) # added 2nd arg 1
        return AES_obj.decrypt(c)

    def __eq__(self, other):
        return self.key == other.key


def test():
    k1 = AES_key.gen_random(0)
    k1_int = k1.as_int()
    k1_bin_str = k1.as_bin_str()
    k1_bin = k1.as_bin()
    k1_hex = k1.as_hex()
    k1_bytes = k1.as_bytes()
    assert k1 == AES_key.from_int(k1_int)
    assert k1 == AES_key.from_bin_str(k1_bin_str)
    assert k1 == AES_key.from_bin(k1_bin)
    assert k1 == AES_key.from_hex(k1_hex)
    assert k1 == AES_key.from_bytes(k1_bytes)
    m = rd.randrange(2 ** 128)
    assert Crypto.Util.number.long_to_bytes(m) == k1.decrypt(k1.encrypt(m))


if __name__ == "__main__":
    test()
