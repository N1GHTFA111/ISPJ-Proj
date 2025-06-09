import hashlib
import secrets

from qiskit import QuantumCircuit, Aer, execute
from qiskit.visualization import plot_histogram
import random

#bb84
#alice same set of base, bob same set of base, alice same set of bits,
# result is same shared key
# Alice generates a random bit string
def generate_bit_string(length):
    return ''.join([str(random.randint(0, 1)) for _ in range(length)])

key_length = 32

# Generating random bit strings for Alice and Bob to determine their bases choices
alice_bases = "01001001100111011001001111010001"
bob_bases = "10001000000101010011101000011110"
print(alice_bases)
print(bob_bases)

# Generate qubits by Alice based on her bit string and chosen bases
def encode_qubits(bits, bases):
    qubits = []
    for i in range(len(bits)):
        qc = QuantumCircuit(1, 1) # Creating a quantum circuit with 1 qubit and 1 classical bit

        # if the base is 0
        if bases[i] == '0':  # Encoding based on basis choice
            # if bit is also 0
            if bits[i] == '0':
                pass  # Do nothing for |0>
            # if bit is 1
            else:
                qc.x(0)  # Apply X gate for |1> Pauli-X gate flip 0 to 1 or 1 to 0
        # if base is 1
        else:
            # if bit is 0
            if bits[i] == '0':
                qc.h(0)  # Apply Hadamard gate for |+> state
            # if bit is also 1
            else:
                qc.x(0)
                qc.h(0)
    return qubits

# alice_bits = generate_bit_string(32)
# alice_qubits = encode_qubits(alice_bits, alice_bases)

# Bob measures qubits based on his chosen bases
def measure_qubits(qubits, bases):
    backend = Aer.get_backend('qasm_simulator')
    measurements = []
    for i in range(len(qubits)):
        if bases[i] == '0':
            qubits[i].measure(0, 0) # Measuring qubit in Z-basis
        else:
            qubits[i].h(0)  # Applying Hadamard gate for X-basis measurement if base is 1 superposition of 1
            qubits[i].measure(0, 0)
        result = execute(qubits[i], backend, shots=1).result() # Obtaining the measured bit
        measured_bit = list(result.get_counts().keys())[0]
        measurements.append(measured_bit)
    return measurements

# bob_measurements = measure_qubits(alice_qubits, bob_bases)

# Compare bases and extract key bits
def extract_key(alice_bases, bob_bases, alice_bits, bob_measurements):
    key = ''
    for i in range(len(alice_bases)):
        if alice_bases[i] == bob_bases[i]:
            key += bob_measurements[i]
    return key

# Length of the key


# Generate qubits by Alice based on her bit string and chosen bases
alice_bits = "11101011001000111010100010101101"
print(alice_bits)
alice_qubits = encode_qubits(alice_bits, alice_bases)

# Bob measures qubits based on his chosen bases
bob_measurements = measure_qubits(alice_qubits, bob_bases)

# Ensure the measurements are of the same length as the key
if len(bob_measurements) < key_length:
    diff = key_length - len(bob_measurements)
    bob_measurements += generate_bit_string(diff)

# Extract the shared key
shared_key = extract_key(alice_bases, bob_bases, alice_bits, bob_measurements)
print("Shared Key:", shared_key)

def hash_key(key):
    hashed_key = hashlib.sha256(key.encode()).hexdigest()
    return hashed_key

def key_lengthen(hashed_key):
    # Derive a longer key using PBKDF2
    salt = secrets.token_bytes(32)  # Generate a random salt
    kdf_key = hashlib.pbkdf2_hmac('sha256', hashed_key.encode(), salt, 10000).hex()  # Adjust iterations as needed
    return kdf_key

def get_128_bit_key(hash):
    # print(hash[:32])
    # print(hash[32:])
    first_half = hashlib.sha256(hash[:32].encode()).hexdigest()
    second_half = hashlib.sha256(hash[32:].encode()).hexdigest()

    return first_half + second_half



hashed_key = hash_key(shared_key)
updated_key = key_lengthen(hashed_key)

print("Shared hashed key:", hashed_key)
print("Shared stretched key:", updated_key)

my_final_shared_key = get_128_bit_key(updated_key)

# encryption part
import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def encrypt(message, password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    f = Fernet(key)
    encrypted_token = f.encrypt(message.encode())
    return encrypted_token, key

def decrypt(encrypted_message, fernet_key):
    f = Fernet(fernet_key)
    decrypted_token = f.decrypt(encrypted_message).decode()
    return decrypted_token


secret_val = "SENTNEL_BETA"

print("Shared key: " + str(my_final_shared_key))
encrypted_secret, key = encrypt(secret_val, my_final_shared_key)
print("Encrypted: " + str(encrypted_secret))
decrypted_secret = decrypt(encrypted_secret, key)
print("Decrypted: " + str(decrypted_secret))




# def key_doubler(hashed_key):
#     # split into 2 sets of 32
#     # then hash separately and join back together
#     set1_hashkey = hashed_key[:32]
#     set2_hashkey = hashed_key[32:]
#
#     hashed_set1 = hashlib.sha512(set1_hashkey.encode()).hexdigest()
#     hashed_set2 = hashlib.sha512(set2_hashkey.encode()).hexdigest()
#
#     return str(hashed_set1)+str(hashed_set2)
#
# new_key = key_doubler(updated_key)
#
# print("New key: ", new_key) # 256 char key very secure