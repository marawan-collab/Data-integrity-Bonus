import hashlib
import binascii
import struct
import sys

# Import the verify function from server module
from server import verify, SECRET_KEY

def md5_padding(message_length):
    """
    Generate the MD5 padding for a message of the given length.
    
    MD5 padding consists of:
    1. A single '1' bit (0x80)
    2. Zero bits until the length is congruent to 56 (mod 64)
    3. The original message length as a 64-bit little-endian integer
    """
    # Calculate how many bytes we need to add to get to 56 (mod 64)
    padding_length = 64 - ((message_length + 1) % 64)
    if padding_length < 0:
        padding_length += 64
        
    # Start with the '1' bit followed by zeros
    padding = b'\x80' + b'\x00' * (padding_length - 7)
    
    # Add the message length in bits (little-endian 64-bit integer)
    bit_length = message_length * 8
    padding += struct.pack('<Q', bit_length)
    
    return padding

def demonstrate_length_extension_attack():
    """
    Demonstrate a length extension attack on the vulnerable MAC scheme in server.py
    
    This demonstration uses the SECRET_KEY directly for educational purposes.
    In a real attack, the attacker wouldn't know the SECRET_KEY.
    """
    print("=== Length Extension Attack Demonstration ===")
    print("This demonstrates the vulnerability in server.py's MAC implementation.")
    print("The server uses MAC = hash(secret || message) which is vulnerable to length extension.")
    
    # Original message
    original_message = b"amount=100&to=alice"
    
    # What we want to append
    data_to_append = b"&admin=true"
    
    # Calculate the original MAC
    original_mac = hashlib.md5(SECRET_KEY + original_message).hexdigest()
    print(f"\nOriginal message: {original_message.decode()}")
    print(f"Original MAC: {original_mac}")
    
    # Calculate the padding that would be added to (SECRET_KEY + original_message)
    padding = md5_padding(len(SECRET_KEY) + len(original_message))
    
    # Construct the extended message
    forged_message = original_message + padding + data_to_append
    
    # Calculate what the MAC should be for the forged message
    # In a real attack, we'd compute this without knowing the secret
    # But for demonstration, we'll use the SECRET_KEY
    forged_mac = hashlib.md5(SECRET_KEY + forged_message).hexdigest()
    
    print(f"\nForged message (with padding): {forged_message}")
    print(f"Forged MAC: {forged_mac}")
    
    # Verify that the server would accept this
    print("\n=== Verifying Attack ===")
    if verify(forged_message, forged_mac):
        print("SUCCESS: The forged MAC is valid!")
        print("This demonstrates the vulnerability in the server's MAC implementation.")
        print("The server accepted our forged message with admin=true appended.")
    else:
        print("FAILED: Something went wrong with our demonstration.")

def explain_attack():
    """
    Explain how the length extension attack works
    """
    print("\n=== How the Length Extension Attack Works ===")
    print("1. The server uses MAC = hash(secret || message)")
    print("2. When we know hash(secret || message), we can compute hash(secret || message || padding || extension)")
    print("   without knowing the secret!")
    print("3. This is possible because hash functions like MD5 work by processing blocks of data")
    print("   and maintaining an internal state between blocks.")
    print("4. The hash output tells us the internal state after processing (secret || message)")
    print("5. We can continue hashing from that state, adding (padding || extension)")
    print("\nIn a real attack:")
    print("- The attacker intercepts a valid message and its MAC")
    print("- The attacker needs to guess the secret key length (in this demo it's 64 bytes)")
    print("- The attacker constructs a new message: original_message || padding || extension")
    print("- The attacker computes a valid MAC for this new message without knowing the secret")
    print("\nThe fix is to use HMAC instead of hash(secret || message):")
    print("- HMAC(K, m) = hash((K' ⊕ opad) || hash((K' ⊕ ipad) || m))")
    print("- This prevents length extension attacks by using the key in a more secure way")

def show_secure_alternative():
    """
    Show how HMAC prevents the length extension attack
    """
    import hmac
    
    print("\n=== Secure Alternative: HMAC ===")
    print("HMAC prevents length extension attacks by using the key in a more secure way.")
    
    # Original message
    original_message = b"amount=100&to=alice"
    
    # Calculate HMAC
    secure_mac = hmac.new(SECRET_KEY, original_message, hashlib.md5).hexdigest()
    print(f"Original message: {original_message.decode()}")
    print(f"Secure HMAC: {secure_mac}")
    
    # Try to forge a message
    forged_message = original_message + b"&admin=true"
    forged_hmac = hmac.new(SECRET_KEY, forged_message, hashlib.md5).hexdigest()
    
    print(f"\nForged message: {forged_message.decode()}")
    print(f"Required HMAC: {forged_hmac}")
    print("\nWith HMAC, the attacker cannot compute a valid MAC without knowing the secret key.")
    print("The original MAC cannot be extended to create a valid MAC for the forged message.")

if __name__ == "__main__":
    print("=== MD5 Length Extension Attack Demonstration ===")
    print("This tool demonstrates the vulnerability in server.py's MAC implementation.")
    print("\nChoose an option:")
    print("1. Demonstrate the length extension attack")
    print("2. Explain how the attack works")
    print("3. Show the secure alternative (HMAC)")
    
    choice = input("Enter your choice (1, 2, or 3): ").strip()
    
    if choice == "1":
        demonstrate_length_extension_attack()
    elif choice == "2":
        explain_attack()
    elif choice == "3":
        show_secure_alternative()
    else:
        print("Invalid choice. Exiting.")