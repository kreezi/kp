from algorithm import symmetricCipherABC

class RC5(symmetricCipherABC.SymmetricCipher):
    def __init__(self, w, R, key, strip_extra_nulls=False, bytes_count=16):
        self.block_size = bytes_count
        self.w = w  # block size (32, 64 or 128 bits)
        self.R = R  # number of rounds (0 to 255)
        self.key = key  # key (0 to 2040 bits)
        self.strip_extra_nulls = strip_extra_nulls
        # some useful constants
        self.T = 2 * (R + 1)
        self.w4 = w // 4
        self.w8 = w // 8
        self.mod = 2 ** self.w
        self.mask = self.mod - 1
        self.b = len(key)

        self.set_key()

    def set_key(self, key=b"0"):
        if key != b"0":
            self.key = key
        self.__keyAlign()
        self.__keyExtend()
        self.__shuffle()

    def __lshift(self, val, n):
        n %= self.w
        return ((val << n) & self.mask) | ((val & self.mask) >> (self.w - n))

    def __rshift(self, val, n):
        n %= self.w
        return ((val & self.mask) >> n) | (val << (self.w - n) & self.mask)

    def __const(self):  # constants generation
        if self.w == 16:
            return 0xB7E1, 0x9E37  # return P, Q values
        elif self.w == 32:
            return 0xB7E15163, 0x9E3779B9
        elif self.w == 64:
            return 0xB7E151628AED2A6B, 0x9E3779B97F4A7C15

    def __keyAlign(self):
        if self.b == 0:  # key is empty
            self.c = 1
        elif self.b % self.w8:
            self.key += b'\x00' * (self.w8 - self.b % self.w8)  # fill key with \x00 bytes
            self.b = len(self.key)
            self.c = self.b // self.w8
        else:
            self.c = self.b // self.w8
        L = [0] * self.c
        for i in range(self.b - 1, -1, -1):
            L[i // self.w8] = (L[i // self.w8] << 8) + self.key[i]
        self.L = L

    def __keyExtend(self):
        P, Q = self.__const()
        self.S = [(P + i * Q) % self.mod for i in range(self.T)]

    def __shuffle(self):
        i, j, A, B = 0, 0, 0, 0
        for k in range(3 * max(self.c, self.T)):
            A = self.S[i] = self.__lshift((self.S[i] + A + B), 3)
            B = self.L[j] = self.__lshift((self.L[j] + A + B), A + B)
            i = (i + 1) % self.T
            j = (j + 1) % self.c

    def encrypt(self, plaintext: bytes) -> bytes:
        A = int.from_bytes(plaintext[:self.w8], byteorder='little')
        B = int.from_bytes(plaintext[self.w8:], byteorder='little')

        A = (A + self.S[0]) % self.mod
        B = (B + self.S[1]) % self.mod

        for i in range(1, self.R + 1):
            A = (self.__lshift((A ^ B), B) + self.S[2 * i]) % self.mod
            B = (self.__lshift((A ^ B), A) + self.S[2 * i + 1]) % self.mod

        return (A.to_bytes(self.w8, byteorder='little') + B.to_bytes(self.w8, byteorder='little'))

    def decrypt(self, ciphertext: bytes) -> bytes:
        A = int.from_bytes(ciphertext[:self.w8], byteorder='little')
        B = int.from_bytes(ciphertext[self.w8:], byteorder='little')

        for i in range(self.R, 0, -1):
            B = self.__rshift(B - self.S[2 * i + 1], A) ^ A
            A = self.__rshift(A - self.S[2 * i], B) ^ B

        B = (B - self.S[1]) % self.mod
        A = (A - self.S[0]) % self.mod

        return (A.to_bytes(self.w8, byteorder='little') + B.to_bytes(self.w8, byteorder='little'))
