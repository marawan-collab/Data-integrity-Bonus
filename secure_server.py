import hashlib
import hmac

SECRET_KEY = b'1f8e2b3a4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1'  # In a real system, this would be securely stored

def generate_mac(message: bytes) -> str:
    """
    Generate a MAC using HMAC-SHA256, which is secure against length extension attacks.
    
    HMAC uses the secret key in a way that prevents length extension attacks:
    HMAC(K, m) = H((K' ⊕ opad) || H((K' ⊕ ipad) || m))
    """
    return hmac.new(SECRET_KEY, message, hashlib.sha256).hexdigest()

def verify(message: bytes, mac: str) -> bool:
    """
    Verify if the provided MAC matches the expected MAC for the message.
    Uses constant-time comparison to prevent timing attacks.
    """
    expected_mac = generate_mac(message)
    return hmac.compare_digest(mac, expected_mac)  # Constant-time comparison

def main():
    # Example message
    message = b"amount=100&to=alice"
    mac = generate_mac(message)
    
    print("=== Secure Server Simulation ===")
    print(f"Original message: {message.decode()}")
    print(f"HMAC: {mac}")
    
    print("\n--- Verifying legitimate message ---")
    if verify(message, mac):
        print("HMAC verified successfully. Message is authentic.\n")
    
    # Test with a forged message - the kind that would work with the vulnerable server
    forged_message = b"amount=100&to=alice" + b"&admin=true"
    # For demonstration, we'll use the original MAC (which should fail)
    forged_mac = mac
    
    print("--- Verifying forged message with original MAC ---")
    if verify(forged_message, forged_mac):
        print("HMAC verified successfully (unexpected).")
    else:
        print("HMAC verification failed (as expected with secure HMAC).")

    # Ask user to paste a forged MAC from the client attack
    print("\n--- Testing against length extension attack ---")
    print("If you've run the attack with client.py, enter the forged MAC below:")
    try:
        user_forged_mac = input("Enter forged MAC from client.py: ").strip()
        # For this demo, we're using a simplified version of what the forged message would be
        # In a real attack, there would be padding bytes between the original message and the appended data
        simplified_forged_message = message + b"&admin=true"
        
        print("Testing with a simplified forged message (without proper padding):")
        if verify(simplified_forged_message, user_forged_mac):
            print("WARNING: HMAC verification succeeded. This shouldn't happen with proper HMAC!")
        else:
            print("SECURE: HMAC verification failed, as expected.")
            
        # If the user has the full forged message with padding bytes
        print("\nIf you have the full forged message with padding bytes from client.py,")
        print("you could test it here, but it should still fail with proper HMAC implementation.")
            
    except KeyboardInterrupt:
        print("\nSkipping forged MAC test.")

if __name__ == "__main__":
    main()