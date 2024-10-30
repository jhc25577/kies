from typing import Union

# from coincurve import PrivateKey, PublicKey

from .config import KIES_CONFIG
from .utils import (
    decapsulate,
    encapsulate,
    generate_key_pair,
    # hex2pk,
    # hex2sk,
    sym_decrypt,
    sym_encrypt,
)

__all__ = ["encrypt", "decrypt", "KIES_CONFIG"]

def encrypt(receiver_pk: Union[str, bytes], msg: bytes) -> bytes:
    """
    Encrypt with receiver's secp256k1 public key

    Parameters
    ----------
    receiver_pk: Union[str, bytes]
        Receiver's public key (hex str or bytes)
    msg: bytes
        Data to encrypt

    Returns
    -------
    bytes
        Encrypted data
    """
    # if isinstance(receiver_pk, str):
    #     pk = hex2pk(receiver_pk)
    if isinstance(receiver_pk, bytes):
        pk = receiver_pk
    else:
        raise TypeError("Invalid public key type")

    # ephemeral_sk = generate_key()
    # ephemeral_pk = ephemeral_sk.public_key.format(
    #     ECIES_CONFIG.is_ephemeral_key_compressed
    # )

    # sym_key = encapsulate(ephemeral_sk, pk)
    sym_key, c = encapsulate(pk)
    encrypted = sym_encrypt(sym_key, msg)
    return c + encrypted, c, encrypted, sym_key

# TODO: change based on other changed methods
# also change based on how kyber works
def decrypt(receiver_sk: Union[str, bytes], msg: bytes) -> bytes:
    """
    Decrypt with receiver's secp256k1 private key

    Parameters
    ----------
    receiver_sk: Union[str, bytes]
        Receiver's private key (hex str or bytes)
    msg: bytes
        Data to decrypt

    Returns
    -------
    bytes
        Plain text
    """
    # if isinstance(receiver_sk, str):
    #     sk = hex2sk(receiver_sk)
    if isinstance(receiver_sk, bytes):
        sk = receiver_sk
    else:
        raise TypeError("Invalid secret key type")

    key_size = KIES_CONFIG.key_size
    c, encrypted = msg[0:key_size], msg[key_size:]
    
    sym_key = decapsulate(sk, c)
    return sym_decrypt(sym_key, encrypted)
