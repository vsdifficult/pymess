from shared.crypto_utils.aead import decrypt_aes256_gcm, encrypt_aes256_gcm
from shared.crypto_utils.keys import IdentityKeyPair, derive_shared_secret, secure_random
from shared.crypto_utils.ratchet import RatchetState


def test_x25519_shared_secret_matches() -> None:
    alice = IdentityKeyPair.generate()
    bob = IdentityKeyPair.generate()

    secret_ab = derive_shared_secret(alice.private_key, bob.public_bytes())
    secret_ba = derive_shared_secret(bob.private_key, alice.public_bytes())

    assert secret_ab == secret_ba


def test_aes_gcm_round_trip() -> None:
    key = secure_random(32)
    nonce = secure_random(12)
    aad = b"header"
    plaintext = b"top secret"

    ciphertext = encrypt_aes256_gcm(key, nonce, plaintext, aad)
    decrypted = decrypt_aes256_gcm(key, nonce, ciphertext, aad)

    assert decrypted == plaintext


def test_ratchet_unique_message_keys() -> None:
    state = RatchetState.initialize(secure_random(32))
    mk1 = state.next_sending_message_key().message_key
    mk2 = state.next_sending_message_key().message_key
    assert mk1 != mk2
