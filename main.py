import numpy as np
import matplotlib.pyplot as plt
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister, transpile
from qiskit.visualization import circuit_drawer as cd  
from qiskit_aer import AerSimulator

# One Time Pad Encryption 
def bits_to_bytes(bits):
    # list of bit to bytes (8 bits per byte)
    n = len(bits) - (len(bits) % 8)
    bytes_list = []
    for i in range(0, n, 8):
        byte_str = ''.join(str(b) for b in bits[i:i+8])
        bytes_list.append(int(byte_str, 2))
    return bytes(bytes_list)

def xor_bytes(data, pad):
    # Elementwise XOR 
    return bytes(a ^ b for a, b in zip(data, pad))

def one_time_pad_encrypt(message, key_bits):
    # Encrypt 
    msg_bytes = message.encode('utf-8')
    key_bytes = bits_to_bytes(key_bits)
    if len(key_bytes) < len(msg_bytes):
        raise ValueError("Not enough key bits to encrypt the message.")
    pad = key_bytes[:len(msg_bytes)]
    return xor_bytes(msg_bytes, pad)

def one_time_pad_decrypt(encrypted, key_bits):
    # Decrypt 
    key_bytes = bits_to_bytes(key_bits)
    pad = key_bytes[:len(encrypted)]
    decrypted = xor_bytes(encrypted, pad)
    return decrypted.decode('utf-8')


# E91 Protocol  
class EnhancedE91Protocol:
    def __init__(self, num_pairs=100):
        self.num_pairs = num_pairs

        # Possible measurement bases 
        # (angles in radians) 
        self.alice_angles = [0, np.pi/8, np.pi/4]
        self.bob_angles   = [-np.pi/8, 0, np.pi/8]

        # Fixed measurement angle (Eve)
        self.eve_angle = np.pi/4

        # CHSH threshold
        # Bell violation gives S > 2
        self.error_threshold = 2

    # Circuit 
    def create_entangled_circuit(self, include_eve=True):
        num_qubits = 3 if include_eve else 2
        qr = QuantumRegister(num_qubits, 'q')    # alice(q[0]), bob(q[1]), eve(q[2])
        cr = ClassicalRegister(num_qubits, 'c')  # classical bit = hold measurements
        qc = QuantumCircuit(qr, cr)
        
        # Bell state on qubits
        qc.h(qr[0])
        qc.cx(qr[0], qr[1]) # 0 (Alice), 1 (Bob)
        if include_eve:
            qc.cx(qr[1], qr[2])
        return qc

    # Measurement basis
    def apply_measurement_rotations(self, qc, alice_basis, bob_basis, include_eve=True):

        # Rotate & measure Alice's qubit
        qc.ry(-2 * self.alice_angles[alice_basis], 0)

        # Rotate and measure Bob's qubit
        qc.ry(-2 * self.bob_angles[bob_basis], 1)
        if include_eve:
            qc.ry(-2 * self.eve_angle, 2)

        # all qubits measured
        qc.measure(list(range(qc.num_clbits)), list(range(qc.num_clbits))) 
        return qc

    def calculate_CHSH_parameter(self, results):
        correlations = {(a, b): 0 for a in range(3) for b in range(3)}
        counts = {(a, b): 0 for a in range(3) for b in range(3)}
        for i in range(len(results['alice_bases'])):
            a_base = results['alice_bases'][i]
            b_base = results['bob_bases'][i]

            # map outcome 0 -> +1 and outcome 1 -> -1
            a_val = 1 if results['alice_results'][i] == 0 else -1
            b_val = 1 if results['bob_results'][i] == 0 else -1
            correlations[(a_base, b_base)] += a_val * b_val
            counts[(a_base, b_base)] += 1
        for key in correlations:
            if counts[key] > 0:
                correlations[key] /= counts[key]
        S = abs(correlations[(0, 0)] - correlations[(0, 2)] +
                correlations[(2, 0)] + correlations[(2, 2)])
        return S

    def run_protocol(self, include_eve=True, backend=None):
        results = {
            'alice_bases': [],
            'bob_bases': [],
            'alice_results': [],
            'bob_results': [],
            'eve_results': [] if include_eve else None,
            'circuits': []
        }

        num_bits = 3 if include_eve else 2
        
        for _ in range(self.num_pairs):
            alice_basis = np.random.choice([0, 1, 2])
            bob_basis = np.random.choice([0, 1, 2])
            results['alice_bases'].append(alice_basis)
            results['bob_bases'].append(bob_basis)
            
            qc = self.create_entangled_circuit(include_eve=include_eve)
            qc = self.apply_measurement_rotations(qc, alice_basis, bob_basis, include_eve=include_eve)
            results['circuits'].append(qc.copy())
            
            # Transpile for backend
            compiled_qc = transpile(qc, backend)

            # Run one shot
            job = backend.run(compiled_qc, shots=1)
            result_obj = job.result()

            # Measurement 
            counts = result_obj.get_counts(compiled_qc)
            if not counts or len(counts) == 0:
                raise ValueError("No counts returned from the simulator.")
            
            # Bit strings in little-endian order
            outcome = list(counts.keys())[0].replace(" ", "")
            if len(outcome) < num_bits:
                outcome = outcome.zfill(num_bits)

            # Reverse to assign 
            # index 0 -> Alice, 1 -> Bob, (2 -> Eve if present)
            outcome = outcome[::-1]
            results['alice_results'].append(int(outcome[0]))
            results['bob_results'].append(int(outcome[1]))
            if include_eve:
                results['eve_results'].append(int(outcome[2]))
        
        results['S_parameter'] = self.calculate_CHSH_parameter(results)
        return results

    # Extract the secure key
    def generate_secure_key(self, results):
        key = []
        for i in range(self.num_pairs):
            if results['alice_bases'][i] == results['bob_bases'][i]:
                key.append(results['alice_results'][i])
        return key

    def visualize_results(self, results):

        # Visualize first circuit
        if results['circuits']:
            plt.figure(figsize=(12, 8))
            cd(results['circuits'][0], output='mpl')
            plt.title("Example E91 Circuit")

        # Correlation matrix
        correlations = np.zeros((3, 3))
        for i in range(len(results['alice_bases'])):
            a_base = results['alice_bases'][i]
            b_base = results['bob_bases'][i]
            if results['alice_results'][i] == results['bob_results'][i]:
                correlations[a_base, b_base] += 1

        plt.figure(figsize=(8, 6))
        plt.imshow(correlations, cmap='Blues')
        plt.colorbar()
        plt.title("Measurement Correlation Matrix")
        plt.xlabel("Bob's Bases")
        plt.ylabel("Alice's Bases")
        return plt



if __name__ == "__main__":
    # Local simulator
    backend = AerSimulator()

    print("Running E91 protocol on [local simulator]")
    # Increase num_pairs = longer secure key
    protocol = EnhancedE91Protocol(num_pairs=150)
    results = protocol.run_protocol(include_eve=True, backend=backend)
    
    # Generate secure keys
    alice_key = protocol.generate_secure_key(results)
    bob_key = protocol.generate_secure_key(results)
    
    # QBER on sifted key
    if alice_key and bob_key:
        errors = sum(1 for a, b in zip(alice_key, bob_key) if a != b)
        qber = errors / len(alice_key)
    else:
        qber = None

    print("\nE91 Protocol Results:")
    print("-------------------------------------------------------------------------------------------------------------------------------------------")
    print(f"Alice's outcomes: {results['alice_results']}")
    print(f"Bob's outcomes:   {results['bob_results']}")
    print(f"Eve's outcomes:   {results['eve_results']}")
    print(f"Alice's bases:    {results['alice_bases']}")
    print(f"Bob's bases:      {results['bob_bases']}")
    print(f"CHSH Parameter S: {results['S_parameter']:.3f}")
    print(f"Secure key (Alice): {alice_key}")
    print(f"Secure key (Bob):   {bob_key}")
    if qber is not None:
        if qber == 0:
            print("\nSuccess: Keys match perfectly! (QBER: 0%)")
        else:
            print(f"\nWarning: Keys do not match perfectly. QBER: {qber * 100:.2f}%")
    else:
        print("\nNo secure key was generated.")
    
    # Secret Message 
    secret_message = "HELLO"

    # Secure key length may be short as only rounds with matching bases are kept
    # Increase num_pairs = longer key
    if len(alice_key) < len(secret_message) * 8:
        print("\nSecure key is too short to encrypt the secret message.")
    else:
        try:
            encrypted_msg = one_time_pad_encrypt(secret_message, alice_key)
            decrypted_msg = one_time_pad_decrypt(encrypted_msg, bob_key)
            print("\nSecret Message Transmission:")
            print(f"Original Message: {secret_message}")
            print(f"Encrypted (bytes): {encrypted_msg}")
            print(f"Decrypted Message: {decrypted_msg}")
            if secret_message == decrypted_msg:
                print("\nSuccess: The secret message was transmitted securely!")
            else:
                print("\nError: Decrypted message does not match the original.")
        except Exception as ex:
            print(f"\nEncryption error: {str(ex)}")
    

    plt = protocol.visualize_results(results)
    plt.show()
