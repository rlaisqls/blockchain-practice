#!/usr/bin/env python3
"""
Bitcoin Programming - Chapters 1-7
Unified module containing all implementations up to Chapter 7
"""

import hashlib
import hmac
import json
import os
import requests
from io import BytesIO
from logging import getLogger
from random import randint

LOGGER = getLogger(__name__)

# ==============================================================================
# Constants
# ==============================================================================

SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

A = 0
B = 7
P = 2**256 - 2**32 - 977
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141


# ==============================================================================
# Helper Functions
# ==============================================================================

def hash160(s):
    """sha256 followed by ripemd160"""
    return hashlib.new('ripemd160', hashlib.sha256(s).digest()).digest()


def hash256(s):
    """two rounds of sha256"""
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def encode_base58(s):
    """Encode bytes to base58 string"""
    count = 0
    for c in s:
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, 'big')
    prefix = '1' * count
    result = ''
    while num > 0:
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result


def encode_base58_checksum(b):
    """Encode bytes with checksum to base58"""
    return encode_base58(b + hash256(b)[:4])


def decode_base58(s):
    """Decode base58 string to bytes"""
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25, byteorder='big')
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError('bad address: {} {}'.format(
            checksum, hash256(combined[:-4])[:4]))
    return combined[1:-4]


def little_endian_to_int(b):
    """Convert little-endian bytes to integer"""
    return int.from_bytes(b, 'little')


def int_to_little_endian(n, length):
    """Convert integer to little-endian bytes of specified length"""
    return n.to_bytes(length, 'little')


def read_varint(s):
    """read_varint reads a variable integer from a stream"""
    i = s.read(1)[0]
    if i == 0xfd:
        return little_endian_to_int(s.read(2))
    elif i == 0xfe:
        return little_endian_to_int(s.read(4))
    elif i == 0xff:
        return little_endian_to_int(s.read(8))
    else:
        return i


def encode_varint(i):
    """encodes an integer as a varint"""
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + int_to_little_endian(i, 8)
    else:
        raise ValueError('integer too large: {}'.format(i))


def encode_num(num):
    """Encode a number for script operations"""
    if num == 0:
        return b''
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()
    while abs_num:
        result.append(abs_num & 0xff)
        abs_num >>= 8
    if result[-1] & 0x80:
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def decode_num(element):
    """Decode a number from script operations"""
    if element == b'':
        return 0
    big_endian = element[::-1]
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7f
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8
        result += c
    if negative:
        return -result
    else:
        return result


# ==============================================================================
# Finite Field Element
# ==============================================================================

class FieldElement:
    """Represents an element in a finite field"""

    def __init__(self, num, prime):
        if num >= prime or num < 0:
            error = 'Num {} not in field range 0 to {}'.format(
                num, prime - 1)
            raise ValueError(error)
        self.num = num
        self.prime = prime

    def __repr__(self):
        return 'FieldElement_{}({})'.format(self.prime, self.num)

    def __eq__(self, other):
        if other is None:
            return False
        return self.num == other.num and self.prime == other.prime

    def __ne__(self, other):
        return not (self == other)

    def __add__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot add two numbers in different Fields')
        num = (self.num + other.num) % self.prime
        return self.__class__(num, self.prime)

    def __sub__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot subtract two numbers in different Fields')
        num = (self.num - other.num) % self.prime
        return self.__class__(num, self.prime)

    def __mul__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot multiply two numbers in different Fields')
        num = (self.num * other.num) % self.prime
        return self.__class__(num, self.prime)

    def __pow__(self, exponent):
        n = exponent % (self.prime - 1)
        num = pow(self.num, n, self.prime)
        return self.__class__(num, self.prime)

    def __truediv__(self, other):
        if self.prime != other.prime:
            raise TypeError('Cannot divide two numbers in different Fields')
        num = (self.num * pow(other.num, self.prime - 2, self.prime)) % self.prime
        return self.__class__(num, self.prime)

    def __rmul__(self, coefficient):
        num = (self.num * coefficient) % self.prime
        return self.__class__(num=num, prime=self.prime)


# ==============================================================================
# Elliptic Curve Point
# ==============================================================================

class Point:
    """Represents a point on an elliptic curve"""

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y
        if self.x is None and self.y is None:
            return
        if self.y**2 != self.x**3 + a * x + b:
            raise ValueError('({}, {}) is not on the curve'.format(x, y))

    def __eq__(self, other):
        return self.x == other.x and self.y == other.y \
            and self.a == other.a and self.b == other.b

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        if self.x is None:
            return 'Point(infinity)'
        elif isinstance(self.x, FieldElement):
            return 'Point({},{})_{}_{} FieldElement({})'.format(
                self.x.num, self.y.num, self.a.num, self.b.num, self.x.prime)
        else:
            return 'Point({},{})_{}_{}'.format(self.x, self.y, self.a, self.b)

    def __add__(self, other):
        if self.a != other.a or self.b != other.b:
            raise TypeError('Points {}, {} are not on the same curve'.format(
                self, other))

        if self.x is None:
            return other
        if other.x is None:
            return self

        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.b)

        if self == other:
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)
        while coef:
            if coef & 1:
                result += current
            current += current
            coef >>= 1
        return result


# ==============================================================================
# secp256k1 Field Element
# ==============================================================================

class S256Field(FieldElement):
    """Finite field element for secp256k1"""

    def __init__(self, num, prime=None):
        super().__init__(num=num, prime=P)

    def __repr__(self):
        return '{:x}'.format(self.num).zfill(64)

    def sqrt(self):
        return self**((P + 1) // 4)


# ==============================================================================
# secp256k1 Point
# ==============================================================================

class S256Point(Point):
    """Point on secp256k1 curve"""

    def __init__(self, x, y, a=None, b=None):
        a, b = S256Field(A), S256Field(B)
        if type(x) == int:
            super().__init__(x=S256Field(x), y=S256Field(y), a=a, b=b)
        else:
            super().__init__(x=x, y=y, a=a, b=b)

    def __repr__(self):
        if self.x is None:
            return 'S256Point(infinity)'
        else:
            return 'S256Point({}, {})'.format(self.x, self.y)

    def __rmul__(self, coefficient):
        coef = coefficient % N
        return super().__rmul__(coef)

    def verify(self, z, sig):
        """Verify a signature"""
        s_inv = pow(sig.s, N - 2, N)
        u = z * s_inv % N
        v = sig.r * s_inv % N
        total = u * G + v * self
        return total.x.num == sig.r

    def sec(self, compressed=True):
        """Return the binary version of the SEC format"""
        if compressed:
            if self.y.num % 2 == 0:
                return b'\x02' + self.x.num.to_bytes(32, 'big')
            else:
                return b'\x03' + self.x.num.to_bytes(32, 'big')
        else:
            return b'\x04' + self.x.num.to_bytes(32, 'big') + \
                self.y.num.to_bytes(32, 'big')

    def hash160(self, compressed=True):
        """Return hash160 of the SEC format"""
        return hash160(self.sec(compressed))

    def address(self, compressed=True, testnet=False):
        """Return the address string"""
        h160 = self.hash160(compressed)
        if testnet:
            prefix = b'\x6f'
        else:
            prefix = b'\x00'
        return encode_base58_checksum(prefix + h160)

    @classmethod
    def parse(cls, sec_bin):
        """Parse a Point from SEC binary format"""
        if sec_bin[0] == 4:
            x = int.from_bytes(sec_bin[1:33], 'big')
            y = int.from_bytes(sec_bin[33:65], 'big')
            return S256Point(x=x, y=y)
        is_even = sec_bin[0] == 2
        x = S256Field(int.from_bytes(sec_bin[1:], 'big'))
        alpha = x**3 + S256Field(B)
        beta = alpha.sqrt()
        if beta.num % 2 == 0:
            even_beta = beta
            odd_beta = S256Field(P - beta.num)
        else:
            even_beta = S256Field(P - beta.num)
            odd_beta = beta
        if is_even:
            return S256Point(x, even_beta)
        else:
            return S256Point(x, odd_beta)


# Generator point for secp256k1
G = S256Point(
    0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
    0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)


# ==============================================================================
# Signature
# ==============================================================================

class Signature:
    """ECDSA Signature"""

    def __init__(self, r, s):
        self.r = r
        self.s = s

    def __repr__(self):
        return 'Signature({:x},{:x})'.format(self.r, self.s)

    def der(self):
        """Return DER format of signature"""
        rbin = self.r.to_bytes(32, byteorder='big')
        rbin = rbin.lstrip(b'\x00')
        if rbin[0] & 0x80:
            rbin = b'\x00' + rbin
        result = bytes([2, len(rbin)]) + rbin
        sbin = self.s.to_bytes(32, byteorder='big')
        sbin = sbin.lstrip(b'\x00')
        if sbin[0] & 0x80:
            sbin = b'\x00' + sbin
        result += bytes([2, len(sbin)]) + sbin
        return bytes([0x30, len(result)]) + result

    @classmethod
    def parse(cls, signature_bin):
        """Parse a signature from DER format"""
        s = BytesIO(signature_bin)
        compound = s.read(1)[0]
        if compound != 0x30:
            raise SyntaxError("Bad Signature")
        length = s.read(1)[0]
        if length + 2 != len(signature_bin):
            raise SyntaxError("Bad Signature Length")
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        rlength = s.read(1)[0]
        r = int.from_bytes(s.read(rlength), 'big')
        marker = s.read(1)[0]
        if marker != 0x02:
            raise SyntaxError("Bad Signature")
        slength = s.read(1)[0]
        s_value = int.from_bytes(s.read(slength), 'big')
        if len(signature_bin) != 6 + rlength + slength:
            raise SyntaxError("Signature too long")
        return cls(r, s_value)


# ==============================================================================
# Private Key
# ==============================================================================

class PrivateKey:
    """Bitcoin Private Key"""

    def __init__(self, secret):
        self.secret = secret
        self.point = secret * G

    def hex(self):
        return '{:x}'.format(self.secret).zfill(64)

    def sign(self, z):
        """Sign a message hash"""
        k = self.deterministic_k(z)
        r = (k * G).x.num
        k_inv = pow(k, N - 2, N)
        s = (z + r * self.secret) * k_inv % N
        if s > N / 2:
            s = N - s
        return Signature(r, s)

    def deterministic_k(self, z):
        """Generate deterministic k value using RFC 6979"""
        k = b'\x00' * 32
        v = b'\x01' * 32
        if z > N:
            z -= N
        z_bytes = z.to_bytes(32, 'big')
        secret_bytes = self.secret.to_bytes(32, 'big')
        s256 = hashlib.sha256
        k = hmac.new(k, v + b'\x00' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        k = hmac.new(k, v + b'\x01' + secret_bytes + z_bytes, s256).digest()
        v = hmac.new(k, v, s256).digest()
        while True:
            v = hmac.new(k, v, s256).digest()
            candidate = int.from_bytes(v, 'big')
            if candidate >= 1 and candidate < N:
                return candidate
            k = hmac.new(k, v + b'\x00', s256).digest()
            v = hmac.new(k, v, s256).digest()

    def wif(self, compressed=True, testnet=False):
        """Return WIF (Wallet Import Format) of the private key"""
        secret_bytes = self.secret.to_bytes(32, 'big')
        if testnet:
            prefix = b'\xef'
        else:
            prefix = b'\x80'
        if compressed:
            suffix = b'\x01'
        else:
            suffix = b''
        return encode_base58_checksum(prefix + secret_bytes + suffix)


# ==============================================================================
# Script Operations
# ==============================================================================

def op_0(stack):
    stack.append(encode_num(0))
    return True


def op_1negate(stack):
    stack.append(encode_num(-1))
    return True


def op_1(stack):
    stack.append(encode_num(1))
    return True


def op_2(stack):
    stack.append(encode_num(2))
    return True


def op_3(stack):
    stack.append(encode_num(3))
    return True


def op_4(stack):
    stack.append(encode_num(4))
    return True


def op_5(stack):
    stack.append(encode_num(5))
    return True


def op_6(stack):
    stack.append(encode_num(6))
    return True


def op_7(stack):
    stack.append(encode_num(7))
    return True


def op_8(stack):
    stack.append(encode_num(8))
    return True


def op_9(stack):
    stack.append(encode_num(9))
    return True


def op_10(stack):
    stack.append(encode_num(10))
    return True


def op_11(stack):
    stack.append(encode_num(11))
    return True


def op_12(stack):
    stack.append(encode_num(12))
    return True


def op_13(stack):
    stack.append(encode_num(13))
    return True


def op_14(stack):
    stack.append(encode_num(14))
    return True


def op_15(stack):
    stack.append(encode_num(15))
    return True


def op_16(stack):
    stack.append(encode_num(16))
    return True


def op_nop(stack):
    return True


def op_if(stack, items):
    if len(stack) < 1:
        return False
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (99, 100):
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == 103:
            current_array = false_items
        elif item == 104:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        items[:0] = false_items
    else:
        items[:0] = true_items
    return True


def op_notif(stack, items):
    if len(stack) < 1:
        return False
    true_items = []
    false_items = []
    current_array = true_items
    found = False
    num_endifs_needed = 1
    while len(items) > 0:
        item = items.pop(0)
        if item in (99, 100):
            num_endifs_needed += 1
            current_array.append(item)
        elif num_endifs_needed == 1 and item == 103:
            current_array = false_items
        elif item == 104:
            if num_endifs_needed == 1:
                found = True
                break
            else:
                num_endifs_needed -= 1
                current_array.append(item)
        else:
            current_array.append(item)
    if not found:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        items[:0] = true_items
    else:
        items[:0] = false_items
    return True


def op_verify(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        return False
    return True


def op_return(stack):
    return False


def op_toaltstack(stack, altstack):
    if len(stack) < 1:
        return False
    altstack.append(stack.pop())
    return True


def op_fromaltstack(stack, altstack):
    if len(altstack) < 1:
        return False
    stack.append(altstack.pop())
    return True


def op_2drop(stack):
    if len(stack) < 2:
        return False
    stack.pop()
    stack.pop()
    return True


def op_2dup(stack):
    if len(stack) < 2:
        return False
    stack.extend(stack[-2:])
    return True


def op_3dup(stack):
    if len(stack) < 3:
        return False
    stack.extend(stack[-3:])
    return True


def op_2over(stack):
    if len(stack) < 4:
        return False
    stack.extend(stack[-4:-2])
    return True


def op_2rot(stack):
    if len(stack) < 6:
        return False
    stack.extend(stack[-6:-4])
    return True


def op_2swap(stack):
    if len(stack) < 4:
        return False
    stack[-4:] = stack[-2:] + stack[-4:-2]
    return True


def op_ifdup(stack):
    if len(stack) < 1:
        return False
    if decode_num(stack[-1]) != 0:
        stack.append(stack[-1])
    return True


def op_depth(stack):
    stack.append(encode_num(len(stack)))
    return True


def op_drop(stack):
    if len(stack) < 1:
        return False
    stack.pop()
    return True


def op_dup(stack):
    if len(stack) < 1:
        return False
    stack.append(stack[-1])
    return True


def op_nip(stack):
    if len(stack) < 2:
        return False
    stack[-2:] = stack[-1:]
    return True


def op_over(stack):
    if len(stack) < 2:
        return False
    stack.append(stack[-2])
    return True


def op_pick(stack):
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    stack.append(stack[-n - 1])
    return True


def op_roll(stack):
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    if n == 0:
        return True
    stack.append(stack.pop(-n - 1))
    return True


def op_rot(stack):
    if len(stack) < 3:
        return False
    stack.append(stack.pop(-3))
    return True


def op_swap(stack):
    if len(stack) < 2:
        return False
    stack.append(stack.pop(-2))
    return True


def op_tuck(stack):
    if len(stack) < 2:
        return False
    stack.insert(-2, stack[-1])
    return True


def op_size(stack):
    if len(stack) < 1:
        return False
    stack.append(encode_num(len(stack[-1])))
    return True


def op_equal(stack):
    if len(stack) < 2:
        return False
    element1 = stack.pop()
    element2 = stack.pop()
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_equalverify(stack):
    return op_equal(stack) and op_verify(stack)


def op_1add(stack):
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(element + 1))
    return True


def op_1sub(stack):
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(element - 1))
    return True


def op_negate(stack):
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    stack.append(encode_num(-element))
    return True


def op_abs(stack):
    if len(stack) < 1:
        return False
    element = decode_num(stack.pop())
    if element < 0:
        stack.append(encode_num(-element))
    else:
        stack.append(encode_num(element))
    return True


def op_not(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_0notequal(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))
    return True


def op_add(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element1 + element2))
    return True


def op_sub(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    stack.append(encode_num(element2 - element1))
    return True


def op_booland(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 and element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_boolor(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 or element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_numequal(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_numequalverify(stack):
    return op_numequal(stack) and op_verify(stack)


def op_numnotequal(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 == element2:
        stack.append(encode_num(0))
    else:
        stack.append(encode_num(1))
    return True


def op_lessthan(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 < element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_greaterthan(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 > element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_lessthanorequal(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 <= element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_greaterthanorequal(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element2 >= element1:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_min(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 < element2:
        stack.append(encode_num(element1))
    else:
        stack.append(encode_num(element2))
    return True


def op_max(stack):
    if len(stack) < 2:
        return False
    element1 = decode_num(stack.pop())
    element2 = decode_num(stack.pop())
    if element1 > element2:
        stack.append(encode_num(element1))
    else:
        stack.append(encode_num(element2))
    return True


def op_within(stack):
    if len(stack) < 3:
        return False
    maximum = decode_num(stack.pop())
    minimum = decode_num(stack.pop())
    element = decode_num(stack.pop())
    if element >= minimum and element < maximum:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_ripemd160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.new('ripemd160', element).digest())
    return True


def op_sha1(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha1(element).digest())
    return True


def op_sha256(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha256(element).digest())
    return True


def op_hash160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    h160 = hash160(element)
    stack.append(h160)
    return True


def op_hash256(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hash256(element))
    return True


def op_checksig(stack, z):
    if len(stack) < 2:
        return False
    sec_pubkey = stack.pop()
    der_signature = stack.pop()[:-1]
    try:
        point = S256Point.parse(sec_pubkey)
        sig = Signature.parse(der_signature)
    except (ValueError, SyntaxError) as e:
        LOGGER.info(e)
        return False
    if point.verify(z, sig):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_checksigverify(stack, z):
    return op_checksig(stack, z) and op_verify(stack)


def op_checkmultisig(stack, z):
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())
    m = decode_num(stack.pop())
    if len(stack) < m + 1:
        return False
    der_signatures = []
    for _ in range(m):
        der_signatures.append(stack.pop()[:-1])
    stack.pop()
    try:
        points = [S256Point.parse(sec) for sec in sec_pubkeys]
        sigs = [Signature.parse(der) for der in der_signatures]
        for sig in sigs:
            if len(points) == 0:
                LOGGER.info("signatures no good or not in right order")
                return False
            while points:
                point = points.pop(0)
                if point.verify(z, sig):
                    break
        stack.append(encode_num(1))
    except (ValueError, SyntaxError):
        return False
    return True


def op_checkmultisigverify(stack, z):
    return op_checkmultisig(stack, z) and op_verify(stack)


def op_checklocktimeverify(stack, locktime, sequence):
    if sequence == 0xffffffff:
        return False
    if len(stack) < 1:
        return False
    element = decode_num(stack[-1])
    if element < 0:
        return False
    if element < 500000000 and locktime > 500000000:
        return False
    if locktime < element:
        return False
    return True


def op_checksequenceverify(stack, version, sequence):
    if sequence & (1 << 31) == (1 << 31):
        return False
    if len(stack) < 1:
        return False
    element = decode_num(stack[-1])
    if element < 0:
        return False
    if element & (1 << 31) == (1 << 31):
        if version < 2:
            return False
        elif sequence & (1 << 31) == (1 << 31):
            return False
        elif element & (1 << 22) != sequence & (1 << 22):
            return False
        elif element & 0xffff > sequence & 0xffff:
            return False
    return True


OP_CODE_FUNCTIONS = {
    0: op_0,
    79: op_1negate,
    81: op_1,
    82: op_2,
    83: op_3,
    84: op_4,
    85: op_5,
    86: op_6,
    87: op_7,
    88: op_8,
    89: op_9,
    90: op_10,
    91: op_11,
    92: op_12,
    93: op_13,
    94: op_14,
    95: op_15,
    96: op_16,
    97: op_nop,
    99: op_if,
    100: op_notif,
    105: op_verify,
    106: op_return,
    107: op_toaltstack,
    108: op_fromaltstack,
    109: op_2drop,
    110: op_2dup,
    111: op_3dup,
    112: op_2over,
    113: op_2rot,
    114: op_2swap,
    115: op_ifdup,
    116: op_depth,
    117: op_drop,
    118: op_dup,
    119: op_nip,
    120: op_over,
    121: op_pick,
    122: op_roll,
    123: op_rot,
    124: op_swap,
    125: op_tuck,
    130: op_size,
    135: op_equal,
    136: op_equalverify,
    139: op_1add,
    140: op_1sub,
    143: op_negate,
    144: op_abs,
    145: op_not,
    146: op_0notequal,
    147: op_add,
    148: op_sub,
    154: op_booland,
    155: op_boolor,
    156: op_numequal,
    157: op_numequalverify,
    158: op_numnotequal,
    159: op_lessthan,
    160: op_greaterthan,
    161: op_lessthanorequal,
    162: op_greaterthanorequal,
    163: op_min,
    164: op_max,
    165: op_within,
    166: op_ripemd160,
    167: op_sha1,
    168: op_sha256,
    169: op_hash160,
    170: op_hash256,
    172: op_checksig,
    173: op_checksigverify,
    174: op_checkmultisig,
    175: op_checkmultisigverify,
    176: op_nop,
    177: op_checklocktimeverify,
    178: op_checksequenceverify,
    179: op_nop,
    180: op_nop,
    181: op_nop,
    182: op_nop,
    183: op_nop,
    184: op_nop,
    185: op_nop,
}

OP_CODE_NAMES = {
    0: 'OP_0',
    76: 'OP_PUSHDATA1',
    77: 'OP_PUSHDATA2',
    78: 'OP_PUSHDATA4',
    79: 'OP_1NEGATE',
    81: 'OP_1',
    82: 'OP_2',
    83: 'OP_3',
    84: 'OP_4',
    85: 'OP_5',
    86: 'OP_6',
    87: 'OP_7',
    88: 'OP_8',
    89: 'OP_9',
    90: 'OP_10',
    91: 'OP_11',
    92: 'OP_12',
    93: 'OP_13',
    94: 'OP_14',
    95: 'OP_15',
    96: 'OP_16',
    97: 'OP_NOP',
    99: 'OP_IF',
    100: 'OP_NOTIF',
    103: 'OP_ELSE',
    104: 'OP_ENDIF',
    105: 'OP_VERIFY',
    106: 'OP_RETURN',
    107: 'OP_TOALTSTACK',
    108: 'OP_FROMALTSTACK',
    109: 'OP_2DROP',
    110: 'OP_2DUP',
    111: 'OP_3DUP',
    112: 'OP_2OVER',
    113: 'OP_2ROT',
    114: 'OP_2SWAP',
    115: 'OP_IFDUP',
    116: 'OP_DEPTH',
    117: 'OP_DROP',
    118: 'OP_DUP',
    119: 'OP_NIP',
    120: 'OP_OVER',
    121: 'OP_PICK',
    122: 'OP_ROLL',
    123: 'OP_ROT',
    124: 'OP_SWAP',
    125: 'OP_TUCK',
    130: 'OP_SIZE',
    135: 'OP_EQUAL',
    136: 'OP_EQUALVERIFY',
    139: 'OP_1ADD',
    140: 'OP_1SUB',
    143: 'OP_NEGATE',
    144: 'OP_ABS',
    145: 'OP_NOT',
    146: 'OP_0NOTEQUAL',
    147: 'OP_ADD',
    148: 'OP_SUB',
    154: 'OP_BOOLAND',
    155: 'OP_BOOLOR',
    156: 'OP_NUMEQUAL',
    157: 'OP_NUMEQUALVERIFY',
    158: 'OP_NUMNOTEQUAL',
    159: 'OP_LESSTHAN',
    160: 'OP_GREATERTHAN',
    161: 'OP_LESSTHANOREQUAL',
    162: 'OP_GREATERTHANOREQUAL',
    163: 'OP_MIN',
    164: 'OP_MAX',
    165: 'OP_WITHIN',
    166: 'OP_RIPEMD160',
    167: 'OP_SHA1',
    168: 'OP_SHA256',
    169: 'OP_HASH160',
    170: 'OP_HASH256',
    171: 'OP_CODESEPARATOR',
    172: 'OP_CHECKSIG',
    173: 'OP_CHECKSIGVERIFY',
    174: 'OP_CHECKMULTISIG',
    175: 'OP_CHECKMULTISIGVERIFY',
    176: 'OP_NOP1',
    177: 'OP_CHECKLOCKTIMEVERIFY',
    178: 'OP_CHECKSEQUENCEVERIFY',
    179: 'OP_NOP4',
    180: 'OP_NOP5',
    181: 'OP_NOP6',
    182: 'OP_NOP7',
    183: 'OP_NOP8',
    184: 'OP_NOP9',
    185: 'OP_NOP10',
}


# ==============================================================================
# Script
# ==============================================================================

def p2pkh_script(h160):
    """Takes a hash160 and returns the p2pkh ScriptPubKey"""
    return Script([0x76, 0xa9, h160, 0x88, 0xac])


class Script:
    """Bitcoin Script"""

    def __init__(self, cmds=None):
        if cmds is None:
            self.cmds = []
        else:
            self.cmds = cmds

    def __repr__(self):
        result = []
        for cmd in self.cmds:
            if type(cmd) == int:
                if OP_CODE_NAMES.get(cmd):
                    name = OP_CODE_NAMES.get(cmd)
                else:
                    name = 'OP_[{}]'.format(cmd)
                result.append(name)
            else:
                result.append(cmd.hex())
        return ' '.join(result)

    def __add__(self, other):
        return Script(self.cmds + other.cmds)

    @classmethod
    def parse(cls, s):
        """Parse a script from a stream"""
        length = read_varint(s)
        cmds = []
        count = 0
        while count < length:
            current = s.read(1)
            count += 1
            current_byte = current[0]
            if current_byte >= 1 and current_byte <= 75:
                n = current_byte
                cmds.append(s.read(n))
                count += n
            elif current_byte == 76:
                data_length = little_endian_to_int(s.read(1))
                cmds.append(s.read(data_length))
                count += data_length + 1
            elif current_byte == 77:
                data_length = little_endian_to_int(s.read(2))
                cmds.append(s.read(data_length))
                count += data_length + 2
            else:
                op_code = current_byte
                cmds.append(op_code)
        if count != length:
            raise SyntaxError('parsing script failed')
        return cls(cmds)

    def raw_serialize(self):
        """Serialize script without length prefix"""
        result = b''
        for cmd in self.cmds:
            if type(cmd) == int:
                result += int_to_little_endian(cmd, 1)
            else:
                length = len(cmd)
                if length < 75:
                    result += int_to_little_endian(length, 1)
                elif length > 75 and length < 0x100:
                    result += int_to_little_endian(76, 1)
                    result += int_to_little_endian(length, 1)
                elif length >= 0x100 and length <= 520:
                    result += int_to_little_endian(77, 1)
                    result += int_to_little_endian(length, 2)
                else:
                    raise ValueError('too long an cmd')
                result += cmd
        return result

    def serialize(self):
        """Serialize script with length prefix"""
        result = self.raw_serialize()
        total = len(result)
        return encode_varint(total) + result

    def evaluate(self, z):
        """Evaluate the script"""
        cmds = self.cmds[:]
        stack = []
        altstack = []
        while len(cmds) > 0:
            cmd = cmds.pop(0)
            if type(cmd) == int:
                operation = OP_CODE_FUNCTIONS[cmd]
                if cmd in (99, 100):
                    if not operation(stack, cmds):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (107, 108):
                    if not operation(stack, altstack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                elif cmd in (172, 173, 174, 175):
                    if not operation(stack, z):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
                else:
                    if not operation(stack):
                        LOGGER.info('bad op: {}'.format(OP_CODE_NAMES[cmd]))
                        return False
            else:
                stack.append(cmd)
        if len(stack) == 0:
            return False
        if stack.pop() == b'':
            return False
        return True


# ==============================================================================
# Transaction Classes
# ==============================================================================

class TxFetcher:
    """Fetch transactions from the blockchain"""
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return 'https://testnet.programmingbitcoin.com'
        else:
            return 'https://mainnet.programmingbitcoin.com'

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = '{}/tx/{}.hex'.format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError('unexpected response: {}'.format(response.text))
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:
                raise ValueError('not the same id: {} vs {}'.format(tx.id(), tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]

    @classmethod
    def load_cache(cls, filename):
        disk_cache = json.loads(open(filename, 'r').read())
        for k, raw_hex in disk_cache.items():
            raw = bytes.fromhex(raw_hex)
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw))
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw))
            cls.cache[k] = tx

    @classmethod
    def dump_cache(cls, filename):
        with open(filename, 'w') as f:
            to_dump = {k: tx.serialize().hex() for k, tx in cls.cache.items()}
            s = json.dumps(to_dump, sort_keys=True, indent=4)
            f.write(s)


class Tx:
    """Bitcoin Transaction"""

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet

    def __repr__(self):
        tx_ins = ''
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + '\n'
        tx_outs = ''
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + '\n'
        return 'tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}'.format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def __str__(self):
        """Detailed string representation with full transaction info"""
        result = f'Transaction:\n'
        result += f'  tx_id: {self.id()}\n'
        result += f'  version: {self.version}\n'
        result += f'  locktime: {self.locktime}\n'
        result += f'  testnet: {self.testnet}\n'
        result += f'\n  Inputs ({len(self.tx_ins)}):\n'
        for i, tx_in in enumerate(self.tx_ins):
            result += f'\n  [{i}] {"-" * 60}\n'
            for line in str(tx_in).split('\n'):
                if line:
                    result += f'    {line}\n'
        result += f'\n  Outputs ({len(self.tx_outs)}):\n'
        for i, tx_out in enumerate(self.tx_outs):
            result += f'\n  [{i}] {"-" * 60}\n'
            for line in str(tx_out).split('\n'):
                if line:
                    result += f'    {line}\n'
        try:
            fee = self.fee()
            result += f'\n  Fee: {fee} satoshis ({fee / 100000000:.8f} BTC)\n'
        except:
            result += f'\n  Fee: (unable to calculate)\n'
        return result

    def id(self):
        """Human-readable hexadecimal of the transaction hash"""
        return self.hash().hex()

    def hash(self):
        """Binary hash of the legacy serialization"""
        return hash256(self.serialize())[::-1]

    @classmethod
    def parse(cls, s, testnet=False):
        """Parse a transaction from a stream"""
        version = little_endian_to_int(s.read(4))
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))
        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet)

    def serialize(self):
        """Returns the byte serialization of the transaction"""
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self):
        """Returns the fee of this transaction in satoshi"""
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(self.testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum

    def sig_hash(self, input_index):
        """Returns the integer representation of the hash that needs to get signed"""
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                result += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    script_sig=tx_in.script_pubkey(self.testnet),
                    sequence=tx_in.sequence,
                ).serialize()
            else:
                result += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    script_sig=Script(),
                    sequence=tx_in.sequence,
                ).serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        result += int_to_little_endian(SIGHASH_ALL, 4)
        h256 = hash256(result)

        return int.from_bytes(h256, 'big')
    def verify_input(self, input_index):
        """Returns whether the input has a valid signature"""
        tx_in = self.tx_ins[input_index]
        script_pubkey = tx_in.script_pubkey(self.testnet)
        z = self.sig_hash(input_index)
        combined = tx_in.script_sig + script_pubkey
        return combined.evaluate(z)

    def verify(self):
        """Verify this transaction"""
        if self.fee() < 0:
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):
                return False
        return True

    def sign_input(self, input_index, private_key, verbose=False):
        '''Signs the input using the private key'''
        if verbose:
            print(f"\n{'='*80}")
            print(f"SIGNING INPUT [{input_index}]")
            print(f"{'='*80}")

        # Get the transaction input
        tx_in = self.tx_ins[input_index]
        if verbose:
            print(f"\nInput to sign:")
            print(f"  prev_tx: {tx_in.prev_tx.hex()}")
            print(f"  prev_index: {tx_in.prev_index}")

        # get the signature hash (z)
        z = self.sig_hash(input_index)
        if verbose:
            print(f"\nSignature Hash (z):")
            print(f"  z (int): {z}")
            print(f"  z (hex): {hex(z)}")

        # Get private key info
        if verbose:
            print(f"\nPrivate Key:")
            print(f"  secret: {private_key.secret}")
            print(f"  public key (SEC): {private_key.point.sec().hex()}")

        # get der signature of z from private key
        signature = private_key.sign(z)
        der = signature.der()
        if verbose:
            print(f"\nSignature:")
            print(f"  r: {signature.r}")
            print(f"  s: {signature.s}")
            print(f"  DER format ({len(der)} bytes): {der.hex()}")

        # append the SIGHASH_ALL to der (use SIGHASH_ALL.to_bytes(1, 'big'))
        sig = der + SIGHASH_ALL.to_bytes(1, 'big')
        if verbose:
            print(f"\nSignature + SIGHASH_ALL:")
            print(f"  Total length: {len(sig)} bytes")
            print(f"  sig hex: {sig.hex()}")

        # calculate the sec
        sec = private_key.point.sec()
        if verbose:
            print(f"\nPublic Key (SEC format):")
            print(f"  Compressed: {len(sec) == 33}")
            print(f"  sec hex ({len(sec)} bytes): {sec.hex()}")

        # initialize a new script with [sig, sec] as the cmds
        script_sig = Script([sig, sec])
        if verbose:
            print(f"\nScriptSig:")
            print(f"  {script_sig}")

            # Calculate hash160 of the public key
            pubkey_hash160 = hash160(sec)
            print(f"\nPublic Key Hash160:")
            print(f"  hash160(pubkey): {pubkey_hash160.hex()}")

            # Generate address from hash160
            testnet_addr = encode_base58_checksum(b'\x6f' + pubkey_hash160)
            mainnet_addr = encode_base58_checksum(b'\x00' + pubkey_hash160)
            print(f"  Testnet address: {testnet_addr}")
            print(f"  Mainnet address: {mainnet_addr}")

        # Get the ScriptPubKey for verification
        if verbose:
            try:
                script_pubkey = tx_in.script_pubkey(self.testnet)
                print(f"\nScriptPubKey (from previous output):")
                print(f"  {script_pubkey}")

                # Extract expected hash160 from ScriptPubKey
                cmds = script_pubkey.cmds
                if len(cmds) == 5 and cmds[0] == 0x76 and cmds[1] == 0xa9:
                    expected_hash160 = cmds[2]
                    print(f"  Expected hash160: {expected_hash160.hex()}")

                    # Compare
                    if pubkey_hash160 == expected_hash160:
                        print(f"  Hash160 Match: ✓ YES")
                    else:
                        print(f"  Hash160 Match: ✗ NO - Wrong private key!")
            except:
                print(f"\nScriptPubKey: (unable to fetch)")

        # change input's script_sig to new script
        self.tx_ins[input_index].script_sig = script_sig

        # return whether sig is valid using self.verify_input
        result = self.verify_input(input_index)

        if verbose:
            print(f"\nVerification Result: {'✓ VALID' if result else '✗ INVALID'}")
            print(f"{'='*80}\n")

        return result


class TxIn:
    """Transaction Input"""

    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xffffffff):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return '{}:{}'.format(
            self.prev_tx.hex(),
            self.prev_index,
        )

    def __str__(self):
        """Detailed string representation with previous transaction info"""
        result = f'TxIn:\n'
        result += f'  prev_tx: {self.prev_tx.hex()}\n'
        result += f'  prev_index: {self.prev_index}\n'
        result += f'  script_sig: {self.script_sig}\n'
        result += f'  sequence: {self.sequence}\n'
        try:
            prev_tx = self.fetch_tx()
            result += f'\n  Previous Transaction Info:\n'
            result += f'    tx_id: {prev_tx.id()}\n'
            result += f'    output[{self.prev_index}]:\n'
            prev_output = prev_tx.tx_outs[self.prev_index]
            result += f'      amount: {prev_output.amount} satoshis ({prev_output.amount / 100000000:.8f} BTC)\n'
            result += f'      script_pubkey: {prev_output.script_pubkey}\n'
        except:
            result += f'  (Unable to fetch previous transaction)\n'
        return result

    @classmethod
    def parse(cls, s):
        """Parse a transaction input from a stream"""
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        """Returns the byte serialization of the transaction input"""
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=False):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=False):
        """Get the outpoint value by looking up the tx hash"""
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=False):
        """Get the ScriptPubKey by looking up the tx hash"""
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].script_pubkey


class TxOut:
    """Transaction Output"""

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return '{}:{}'.format(self.amount, self.script_pubkey)

    def __str__(self):
        """Detailed string representation"""
        result = f'TxOut:\n'
        result += f'  amount: {self.amount} satoshis ({self.amount / 100000000:.8f} BTC)\n'
        result += f'  script_pubkey: {self.script_pubkey}\n'
        # Try to extract address
        try:
            mainnet_addr = self.address(testnet=False)
            testnet_addr = self.address(testnet=True)
            if mainnet_addr:
                result += f'  mainnet address: {mainnet_addr}\n'
                result += f'  testnet address: {testnet_addr}\n'
        except:
            pass
        return result

    @classmethod
    def parse(cls, s):
        """Parse a transaction output from a stream"""
        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)

    def serialize(self):
        """Returns the byte serialization of the transaction output"""
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result

    def address(self, testnet=False):
        """Extract the address from P2PKH or P2SH ScriptPubKey"""
        # P2PKH: OP_DUP OP_HASH160 <20-byte-hash> OP_EQUALVERIFY OP_CHECKSIG
        # P2SH: OP_HASH160 <20-byte-hash> OP_EQUAL

        cmds = self.script_pubkey.cmds

        # P2PKH detection: [118, 169, <20-bytes>, 136, 172]
        if len(cmds) == 5 and cmds[0] == 0x76 and cmds[1] == 0xa9 and \
           cmds[3] == 0x88 and cmds[4] == 0xac:
            # Extract hash160
            h160 = cmds[2]
            # Mainnet: 0x00, Testnet: 0x6f
            prefix = b'\x6f' if testnet else b'\x00'
            return encode_base58_checksum(prefix + h160)

        # P2SH detection: [169, <20-bytes>, 135]
        elif len(cmds) == 3 and cmds[0] == 0xa9 and cmds[2] == 0x87:
            # Extract hash160
            h160 = cmds[1]
            # Mainnet: 0x05, Testnet: 0xc4
            prefix = b'\xc4' if testnet else b'\x05'
            return encode_base58_checksum(prefix + h160)

        else:
            return None  # Unknown script type


def demo_fetch_transaction(tx_id, testnet=True):
    """
    Fetch and display a transaction with serialization test

    Args:
        tx_id: Transaction ID to fetch
        testnet: Whether to use testnet
    """
    print("\n" + "=" * 80)
    print("Example 1: Fetch and Deserialize Real Transaction")
    print("=" * 80)
    print(f"\nFetching transaction: {tx_id}")

    try:
        tx = TxFetcher.fetch(tx_id, testnet)
        print("\n" + "-" * 80)
        print("Transaction Details:")
        print("-" * 80)
        print(str(tx))

        # Serialize and deserialize test
        serialized = tx.serialize()
        print("\n" + "-" * 80)
        print("Serialization Test:")
        print("-" * 80)
        print(f"Serialized hex ({len(serialized)} bytes):")
        print(serialized.hex())

        # Parse it back
        deserialized_tx = Tx.parse(BytesIO(serialized))
        print(f"\nDeserialized tx_id: {deserialized_tx.id()}")
        print(f"Original tx_id:     {tx.id()}")
        print(f"Match: {deserialized_tx.id() == tx.id()}")

        # Extract addresses from outputs
        print("\n" + "-" * 80)
        print("Output Address Extraction:")
        print("-" * 80)
        for i, tx_out in enumerate(tx.tx_outs):
            print(f"\nOutput [{i}]:")
            print(f"  Amount: {tx_out.amount} satoshis ({tx_out.amount / 100000000:.8f} BTC)")
            mainnet_addr = tx_out.address(testnet=False)
            testnet_addr = tx_out.address(testnet=True)
            if mainnet_addr:
                print(f"  Mainnet Address: {mainnet_addr}")
                print(f"  Testnet Address: {testnet_addr}")
            else:
                print(f"  Address: (Unknown script type)")

    except Exception as e:
        print(f"Error fetching transaction: {e}")
        print("Skipping transaction fetch example (network may be unavailable)")


def demo_create_keys(seed):
    """
    Create keys and addresses from seeds

    Args:
        seed1: First seed string
        seed2: Second seed string

    Returns:
        Tuple of (priv1, priv2, addr1, addr2)
    """
    print("\n" + "=" * 80)
    print("Example 2: Create Keys and Addresses")
    print("=" * 80)

    secret = little_endian_to_int(hash256(seed.encode()))
    priv = PrivateKey(secret=secret)
    public_key = priv.point
    print(f"\nSecret: {secret}")
    print(f"Public Key (compressed SEC):")
    print(f"  {public_key.sec(compressed=True).hex()}")
    testnet_address = public_key.address(compressed=True, testnet=True)
    print(f"Testnet address: {testnet_address}")

    return priv, testnet_address


def demo_create_transaction(prev_tx_ids, prev_indices, target_address,
                            target_amount, private_keys, testnet=True, verbose=False):
    """
    Create and sign a transaction

    Args:
        prev_tx_ids: List of previous transaction IDs (hex strings)
        prev_indices: List of previous output indices
        target_address: Target address for output
        target_amount: Amount in BTC
        private_keys: List of private keys for signing inputs
        testnet: Whether to use testnet
        verbose: Whether to show detailed signing info

    Returns:
        Signed transaction object
    """
    print("\n" + "=" * 80)
    print("Example 3: Create and Sign Transaction")
    print("=" * 80)

    print(f"\nCreating transaction:")
    for i, (tx_id, idx) in enumerate(zip(prev_tx_ids, prev_indices)):
        print(f"  Input {i}: {tx_id}:{idx}")
    print(f"  Output: {target_amount} BTC to {target_address}")

    # Create inputs
    tx_ins = []
    for tx_id, prev_index in zip(prev_tx_ids, prev_indices):
        prev_tx_bytes = bytes.fromhex(tx_id)
        tx_ins.append(TxIn(prev_tx_bytes, prev_index))

    # Create outputs
    tx_outs = []
    h160 = decode_base58(target_address)
    script_pubkey = p2pkh_script(h160)
    target_satoshis = int(target_amount * 100000000)
    tx_outs.append(TxOut(target_satoshis, script_pubkey))

    # Create transaction
    tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=testnet)

    # Sign inputs
    print(f"\nSigning {len(tx_ins)} input(s)...")
    for i, priv_key in enumerate(private_keys):
        sign_result = tx_obj.sign_input(i, priv_key, verbose=verbose)
        print(f"  Input {i} signed: {sign_result}")

    print(f"\nSerialized transaction:")
    print(f"  {tx_obj.serialize().hex()}")

    # Show output addresses
    print(f"\nTransaction outputs:")
    for i, tx_out in enumerate(tx_obj.tx_outs):
        print(f"\n  Output [{i}]:")
        print(f"    Amount: {tx_out.amount} satoshis ({tx_out.amount / 100000000:.8f} BTC)")
        testnet_addr = tx_out.address(testnet=testnet)
        print(f"    Address: {testnet_addr}")

    return tx_obj


if __name__ == '__main__':
    # Load environment variables with defaults
    TX_ID = os.getenv('DEMO_TX_ID', '')
    PREV_TX_1 = os.getenv('DEMO_PREV_TX_1', '')
    PREV_TX_2 = os.getenv('DEMO_PREV_TX_2', '')
    TARGET_ADDRESS = os.getenv('DEMO_TARGET_ADDRESS', '')
    TARGET_AMOUNT = float(os.getenv('DEMO_TARGET_AMOUNT', '0.000429'))
    SEED1 = os.getenv('DEMO_SEED1', '')
    SEED2 = os.getenv('DEMO_SEED2', '')

    demo_fetch_transaction(TX_ID, testnet=True)
    priv1, addr1 = demo_create_keys(SEED1)
    priv2, addr2 = demo_create_keys(SEED2)

    demo_create_transaction(
        prev_tx_ids=[PREV_TX_1, PREV_TX_2],
        prev_indices=[0, 0],
        target_address=TARGET_ADDRESS,
        target_amount=TARGET_AMOUNT,
        private_keys=[priv1, priv2],
        testnet=True,
        verbose=True
    )

    print("\n" + "=" * 80)
    print("All examples completed!")
    print("=" * 80)

