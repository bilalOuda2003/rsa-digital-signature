"""
RSA Digital Signature demo (Software Security - Chapter 2)
Flow: hash(message) -> sign with PRIVATE key -> verify with PUBLIC key.
Uses RSA-2048, SHA-256 and PSS padding via the 'cryptography' package.
Usage:  python rsa_signature.py            (normal run)
        python rsa_signature.py --tamper   (message altered after signing)
"""
import sys
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

PSS = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH)


def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message, PSS, hashes.SHA256())


def verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, PSS, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def main():
    tamper = "--tamper" in sys.argv
    print("=== RSA Digital Signature Demo ===")

    print("\n[1] Generating RSA-2048 key pair ...")
    private_key, public_key = generate_keys()
    pub_pem = public_key.public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo)
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    with open("public_key.pem", "wb") as f:
        f.write(pub_pem)
    print("    Keys saved: private_key.pem , public_key.pem")
    print("    Public key (first line):", pub_pem.decode().splitlines()[1][:40] + "...")

    message = b"Transfer $1000 to Mark"
    print("\n[2] Signer (Bob) prepares the message:")
    print("    Message  :", message.decode())
    print("    SHA-256  :", hashlib.sha256(message).hexdigest())

    signature = sign(private_key, message)
    print("\n[3] Bob signs the hash with his PRIVATE key:")
    print("    Signature length :", len(signature) * 8, "bits")
    print("    Signature (hex)  :", signature.hex()[:64] + "...")

    received = b"Transfer $1000 to Oscar" if tamper else message
    print("\n[4] Receiver (Alice) gets the message:")
    print("    Received :", received.decode())
    print("    SHA-256  :", hashlib.sha256(received).hexdigest())

    print("\n[5] Alice verifies using Bob's PUBLIC key ...")
    if verify(public_key, received, signature):
        print("    RESULT: Signature VALID  -> authentic sender + message unchanged")
    else:
        print("    RESULT: Signature INVALID -> message altered or wrong signer!")


if __name__ == "__main__":
    main()
