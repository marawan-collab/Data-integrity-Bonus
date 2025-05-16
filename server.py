import hashlib

SECRET_KEY = b'1f8e2b3a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1'  # Unknown to attacker

def generate_mac(message: bytes) -> str:
    """
    Generate a MAC using a naive and vulnerable approach:
    MAC = hash(secret || message)
    
    This is vulnerable to length extension attacks.
    """
    return hashlib.md5(SECRET_KEY + message).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    """
    Verify if the provided MAC matches the expected MAC for the message.
    """
    expected_mac = generate_mac(message)
    return mac == expected_mac  # Vulnerable to timing attacks

def main():
    # Example message
    message = b"amount=100&to=alice"
    mac = generate_mac(message)
    
    print("=== Server Simulation ===")
    print(f"Original message: {message.decode()}")
    print(f"MAC: {mac}")
    
    print("\n--- Verifying legitimate message ---")
    if verify(message, mac):
        print("MAC verified successfully. Message is authentic.\n")
    
    # Simulated attacker-forged message
    forged_message = b"amount=100&to=alice" + b"&admin=true"
    forged_mac = mac  # Attacker provides same MAC (initially)
    
    print("--- Verifying forged message ---")
    if verify(forged_message, forged_mac):
        print("MAC verified successfully (unexpected).")
    else:
        print("MAC verification failed (as expected).")

if __name__ == "__main__":
    main()