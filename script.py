from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import DES3, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import random
import time
import string
import matplotlib.pyplot as plt

class Timer:
    def __init__(self):
        # Initierar timern med start- och sluttid
        self.start_time = None
        self.end_time = None

    def start(self):
        # Startar timern
        self.start_time = time.perf_counter()

    def end(self):
        # Stoppar timern
        self.end_time = time.perf_counter()

    def elapsed_time_ns(self):
        # Returnerar den förflutna tiden i nanosekunder
        if self.start_time is None or self.end_time is None:
            raise ValueError("Timern har inte startats eller stoppats")
        return (self.end_time - self.start_time) * 1e9  # Konvertera till nanosekunder

    def elapsed_time_ms(self):
        # Returnerar den förflutna tiden i millisekunder
        if self.start_time is None or self.end_time is None:
            raise ValueError("Timern har inte startats eller stoppats")
        return (self.end_time - self.start_time) * 1e3  # Konvertera till millisekunder

# AES-kryptering
# Krypterar data med AES-algoritmen
# Returnerar krypterad data och tid

def aes_encrypt(data):
    timer = Timer()
    timer.start()

    key = get_random_bytes(16)  # AES kräver nyckel på 16, 24 eller 32 byte
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext_padded = pad(data, AES.block_size)
    ciphertext = cipher.encrypt(plaintext_padded)  # Fyller ut data till blockstorlek

    timer.end()
    return {
        'non_encrypted_length': len(data),
        'encrypted_length': len(ciphertext),
        'time': timer.elapsed_time_ns()
    }

# DES-kryptering
# Krypterar data med DES-algoritmen
# Returnerar krypterad data och tid

def des_encrypt(data):
    timer = Timer()
    timer.start()

    key = DES3.adjust_key_parity(get_random_bytes(24))  # 24 byte-nyckel för Triple DES
    iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)

    plaintext_padded = pad(data, DES3.block_size)
    ciphertext = cipher.encrypt(plaintext_padded)  # Fyller ut data till blockstorlek

    timer.end()
    return {
        'non_encrypted_length': len(data),
        'encrypted_length': len(ciphertext),
        'time': timer.elapsed_time_ns()
    }

# RSA-kryptering
# Krypterar data med RSA-algoritmen
# Returnerar krypterad data och tid

def rsa_encrypt(data):
    timer = Timer()
    timer.start()

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    timer.end()
    return {
        'non_encrypted_length': len(data),
        'encrypted_length': len(ciphertext),
        'time': timer.elapsed_time_ns()
    }

# ECC-kryptering
# Krypterar data med ECC och AES-256
# Returnerar krypterad data och tid

def ecc_encrypt(data):
    timer = Timer()
    timer.start()

    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # Kryptering med AES-256 med den delade ECC-nyckeln
    iv = get_random_bytes(16)
    cipher = AES.new(shared_key[:32], AES.MODE_CBC, iv)  # AES kräver 256-bitars (32-byte) nyckel

    plaintext_padded = pad(data, 16)
    ciphertext = cipher.encrypt(plaintext_padded)  # Fyller ut data till blockstorlek

    timer.end()
    return {
        'non_encrypted_length': len(data),
        'encrypted_length': len(ciphertext),
        'time': timer.elapsed_time_ns()
    }

# Generera en slumpmässig sträng av en given längd

def generate_random_string(length):
    if length <= 0:
        raise ValueError("Längden måste vara ett positivt heltal")
    characters = string.ascii_letters + string.digits  # Innehåller A-Z, a-z och 0-9
    return ''.join(random.choices(characters, k=length))

# Simulerar kryptering av data med olika algoritmer

def simulate_encryption_data():
    data_points = []
    for i in range(2, 50):
        data = generate_random_string(i).encode("utf-8")
        data_points.append({
            "length": i,
            "AES": aes_encrypt(data),
            "DES": des_encrypt(data),
            "RSA": rsa_encrypt(data),
            "ECC": ecc_encrypt(data),
        })
    return data_points

# Simulera data

data_points = simulate_encryption_data()

# Förbered data för plottning
lengths = [point["length"] for point in data_points]
aes_times = [point["AES"]["time"] for point in data_points]
des_times = [point["DES"]["time"] for point in data_points]
rsa_times = [point["RSA"]["time"] for point in data_points]
ecc_times = [point["ECC"]["time"] for point in data_points]

# Plotta krypteringstider
plt.figure(figsize=(12, 6))
plt.plot(lengths, aes_times, label="AES", marker='o')
plt.plot(lengths, des_times, label="DES", marker='x')
plt.plot(lengths, rsa_times, label="RSA", marker='s')
plt.plot(lengths, ecc_times, label="ECC", marker='d')

# Lägg till etiketter och titel
plt.xlabel("Data Length (bytes)")
plt.ylabel("Encryption Time (microseconds, log scale)")
plt.title("Encryption Times for Various Algorithms (Log Scale)")
plt.yscale('log')  # Tillämpa logaritmisk skala på y-axeln
plt.legend()
plt.grid(True, which="both", linestyle="--", linewidth=0.5)

# Visa plotten
plt.show()
