
from base64 import b64encode, b64decode
from nacl.public import PrivateKey


def generate_key():
    """Generates a new private key"""

    private = PrivateKey.generate()
    return b64encode(bytes(private)).decode("ascii")


def public_key(private_key):
    """Given a private key, returns the corresponding public key"""

    private = PrivateKey(b64decode(private_key))
    return b64encode(bytes(private.public_key)).decode("ascii")
