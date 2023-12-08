import struct

class SHA1:
    def __init__(self):
        # Ініціалізація початкових значень хеш-функції
        self.h0 = 0x67452301
        self.h1 = 0xEFCDAB89
        self.h2 = 0x98BADCFE
        self.h3 = 0x10325476
        self.h4 = 0xC3D2E1F0

    def process_block(self, block):
        # Ініціалізація робочих змінних для обробки блоку
        w = [0] * 80

        # Розбиття блоку на 16 32-бітних слов
        for i in range(16):
            w[i] = int.from_bytes(block[i * 4:i * 4 + 4], 'big')

        # Розрахунок розширених слів
        for i in range(16, 80):
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]) << 1
            w[i] &= 0xFFFFFFFF

        # Ініціалізація змінних хеш-функції
        a, b, c, d, e = self.h0, self.h1, self.h2, self.h3, self.h4

        # Основний цикл обробки блоку
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = (a << 5) + f + e + k + w[i]
            temp &= 0xFFFFFFFF
            e = d
            d = c
            c = (b << 30) + (b >> 2)
            c &= 0xFFFFFFFF
            b = a
            a = temp

        # Оновлення значень хеш-функції
        self.h0 = (self.h0 + a) & 0xFFFFFFFF
        self.h1 = (self.h1 + b) & 0xFFFFFFFF
        self.h2 = (self.h2 + c) & 0xFFFFFFFF
        self.h3 = (self.h3 + d) & 0xFFFFFFFF
        self.h4 = (self.h4 + e) & 0xFFFFFFFF

    def sha1(self, message):
        # Перевірка, чи коректно передано повідомлення
        if not isinstance(message, bytes):
            message = message.encode('utf-8')

        # Вивід відкритого повідомлення
        print("Відкрите повідомлення:", message.decode('utf-8'))

        # Довжина повідомлення у бітах
        message_bit_length = len(message) * 8

        # Додавання біту "1" до повідомлення
        message += b'\x80'

        # Додавання бітів "0" до повідомлення, щоб довжина була кратно 512
        while (len(message) + 64) % 512 != 0:
            message += b'\x00'

        # Додавання довжини повідомлення у вигляді 64-бітного цілого числа
        message += struct.pack('>Q', message_bit_length)

        # Обробка блоків повідомлення
        for i in range(0, len(message), 64):
            block = message[i:i+64]
            self.process_block(block)

        # Формування фінального хешу
        digest = struct.pack('>I', self.h0) + struct.pack('>I', self.h1) + struct.pack('>I', self.h2) + struct.pack('>I', self.h3) + struct.pack('>I', self.h4)

        # Вивід SHA-1 хешу
        print("SHA-1 Hash:", digest.hex())

# Приклад використання
sha1 = SHA1()
message = "Nikita"
sha1.sha1(message)
