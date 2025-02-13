# E91 Quantum Key Distribution (QKD) Protocol Implementation

This project implements the **E91 Quantum Key Distribution (QKD) protocol** using Qiskit. The protocol ensures secure key exchange between two parties, **Alice and Bob**, using entangled quantum states, while also detecting potential eavesdroppers (**Eve**).

## 📜 Overview
The E91 protocol utilizes **quantum entanglement** to distribute a cryptographic key securely. If an eavesdropper attempts to intercept the communication, their presence is revealed due to the disturbance in quantum measurements.

### 🔹 Key Features:
- **Quantum entanglement simulation** using Qiskit's `QuantumCircuit`.
- **Measurement in random bases** for Alice and Bob.
- **Bell test (CHSH inequality) evaluation** to detect eavesdropping.
- **One-time pad encryption** for secure message transmission.
- **Comparison of secure key vs. eavesdropped key (if Eve is present).**

## 📦 Installation
Ensure you have Python installed and install the required dependencies:

```sh
pip install qiskit numpy matplotlib qiskit-ibm-provider pylatexenc qiskit-aer 
```

## 🚀 Usage
Run the Python script to execute the E91 protocol simulation:

```sh
python main.py
```

### 🔄 Steps Involved:
1. **Generate entangled qubits** using Qiskit.
2. **Alice and Bob perform measurements** in randomly chosen bases.
3. **CHSH inequality is tested** to check for eavesdropping.
4. **Shared key is extracted** and verified for security.
5. **Encrypt and decrypt a message** using the final secure key.

## 📊 Results and Analysis
- If Eve is absent, Alice and Bob should obtain highly correlated keys.
- If Eve tries to intercept, the CHSH violation test will indicate eavesdropping, reducing the usable key length.

## 🔐 Security Considerations
- The one-time pad encryption ensures **perfect secrecy** when the key length matches the message length.
- CHSH inequality violation test helps detect eavesdropping attempts.
- Real-world implementation requires noise-tolerant quantum hardware.

## 📷 Visualization
The project includes circuit diagrams and measurement statistics for analysis:
- **Quantum Circuit Diagram** for entanglement setup.
- **Measurement Outcomes** to compare Alice, Bob, and Eve's results.
- **Secure Key Extraction** results to analyze security.

