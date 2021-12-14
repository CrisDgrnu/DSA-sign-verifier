from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

# Typing
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey.DSA import DsaKey
from Crypto.Signature.DSS import FipsDsaSigScheme
from typing import List


def verify(hashed_message_1: SHA256Hash, hashed_message_2: SHA256Hash, signature_1: str, signature_2: str) -> None:
    file = open('./keys/public.key')
    public_key = DSA.import_key(file.read())
    verifier = DSS.new(public_key, 'fips-186-3')
    print(verifier)

    check_signature(verifier, "# CHECK IF THE SIGNATURE IS VALID FOR BOTH MESSAGES",
                    hashed_message_1, hashed_message_2, signature_1, signature_2)

    check_signature(verifier, "# CHECK THAT THE SIGNATURE IS NOT VALID IF WE SWAP THEM",
                    hashed_message_1, hashed_message_2, signature_2, signature_1)


def check_signature(verifier: FipsDsaSigScheme, message: str,
                    hashed_message_1: SHA256Hash, hashed_message_2: SHA256Hash,
                    signature_1: str, signature_2: str):
    print(message)
    try:
        verifier.verify(hashed_message_1, signature_1)
        verifier.verify(hashed_message_2, signature_2)
        print("-> Both messages are authentic\n")
    except ValueError:
        print("-> The messages are not authentic\n")


def sign(keys: DsaKey, hashed_message: SHA256Hash) -> str:
    signer = DSS.new(keys, 'fips-186-3')
    signature = signer.sign(hashed_message)
    return signature


def hash(message_plain_list: List[str]) -> SHA256Hash:

    hashed_string = SHA256.new(str.encode(message_plain_list[0]))

    for line in range(1, len(message_plain_list)):
        hashed_string.update(str.encode(message_plain_list[line]))

    return hashed_string


def read_file() -> List[str]:
    with open('files/message.txt') as f:
        lines = f.readlines()
    return lines


def create_keys() -> DsaKey:

    keys = DSA.generate(2048)

    # Private key
    with open("./keys/private.key", "wb") as file:
        file.write(keys.exportKey("PEM"))  # DER

    # Public key
    public_key = keys.publickey()
    with open("./keys/public.key", "wb") as file:
        file.write(public_key.exportKey("PEM"))  # DER

    return keys


def main() -> None:

    # Generate the keys
    keys = create_keys()

    # Read the message from file
    message_list = read_file()

    # Generate 2 different messages
    hashed_message_1 = hash(message_list)
    hashed_message_2 = hash("Another message")

    # Generate both signatures
    signature_1 = sign(keys, hashed_message_1)
    signature_2 = sign(keys, hashed_message_2)

    # Verify that the authors of the hashed messages by its signature
    verify(hashed_message_1, hashed_message_2, signature_1, signature_2)


if __name__ == "__main__":
    main()
