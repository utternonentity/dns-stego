from src.stego import DomainDecoder, DomainEncoder
from src.utils.crypto import AESCipher


def test_roundtrip_base32():
    message = b"secret message"
    password = "password"
    encoder = DomainEncoder("example.com", chunk_size=5)
    domains = encoder.encode(AESCipher(password).encrypt(message))

    decoder = DomainDecoder("example.com")
    decrypted = AESCipher(password).decrypt(decoder.decode(domains))

    assert decrypted == message
