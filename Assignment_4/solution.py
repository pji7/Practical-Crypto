"""
Solution to Assignment 4

Python version 3.9 or later.

Your final submission must contain the following functions:
    - compute_ecdsa_sk(params)
    - modify_user_storage(params)

You might require the following packages to implement your solution:
    - pycryptodome: Install by running `pip install pycryptodome`.
    - tinyec: Install by running `pip install tinyec`.
    - dissononce: Install by running `pip install dissononce`.
See 'problem.py' for usage examples.
"""
import hashlib

from Crypto.Cipher.DES3 import key_size
from tinyec.registry import get_curve
from problem import ECDSA

from dissononce.processing.impl.symmetricstate import SymmetricState
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.cipher.chachapoly import ChaChaPolyCipher
from dissononce.dh.x25519.x25519 import X25519DH, PrivateKey
from dissononce.hash.sha512 import SHA512Hash
from problem import KHandShakeState


def compute_ecdsa_sk(params):
    """
    Recovers the server's ECDSA secret key.

    Parameters:
        params (AttackParams): An instance of AttackParams (defined in 'problem.py').

    Returns:
        int: The recovered ECDSA secret key.
    """
    # Use the P256 curve.
    curve = get_curve("secp256r1")
    # N is the order of the group.
    N = curve.field.n

    # dict to store viewed values.
    signatures = {}

    while True:
        msg, sig = params.check_update()
        r, s = sig

        # Check this r value is existed in dict.
        # If we see this r before, try to compute the key.
        if r in signatures:
            msg1, s1 = signatures[r] # old (msg, sig).
            msg2, s2 = msg, s        # new (msg, sig).

            # Compute messages' hash. => ECDSA.hash_msg_to_int(msg, N).
            e1 = int.from_bytes(hashlib.sha256(msg1).digest(), byteorder="big") % N
            e2 = int.from_bytes(hashlib.sha256(msg2).digest(), byteorder="big") % N

            # Try to recover key.
            try:
                # Compute s1 - s2 mod N.
                s_diff = (s1 - s2) % N

                # Compute e1 - e2 mod N.
                e_diff = (e1 - e2) % N

                # Recover k.
                k = (e_diff * pow(s_diff, -1, N)) % N

                # Recover sk.
                sk = ((s1 * k - e1) * pow(r, -1, N)) % N

                #print(sk)
                return sk

            except ValueError:
                continue

        # Update new value of messages and signatures if not exist.
        signatures[r] = (msg, s)


def modify_user_storage(params, target_data):
    """
    Modify the registered user's storage.

    Parameters:
        params (AttackParams): An instance of AttackParams (defined in 'problem.py').

        target_data (bytes): The user's storage should be set to this byte string at the end of the
            attack.

    Returns: No return value.
    """
    # params {
    #   client_static_pk
    #   server_static_pk
    #   get_client_handshake_message()
    #   check_update()
    #   update_storage(msg)
    #   }

    # Step 1 : Get known values:
    # Server-side : server_ecdsa_sk, server_static_sk, server_public_sk
    # Client-side : client_static_pk, client_msg
    server_ecdsa_sk = compute_ecdsa_sk(params)
    sk_bytes = server_ecdsa_sk.to_bytes(16, byteorder="big")
    server_static_sk = PrivateKey(sk_bytes + b"0" * 16) # s
    client_static_pk = params.client_static_pk
    server_static_pk = params.server_static_pk
    client_msg = params.get_client_handshake_message()

    # print("server_ecdsa_sk: ", server_ecdsa_sk)
    # print("server_static_sk: ", server_static_sk)
    # print("client_pk: ", client_pk.data.hex())
    # print("server_pk: ", server_pk.data.hex())
    # print("client_msg: ", client_msg.hex())

    # Step 2 : Stimulate Noise K initialized process:
    # Define diffie-hellman, protocol_name, prologue.
    DH = X25519DH()
    protocol_name = "Noise_K_25519_ChaChaPoly_SHA256"
    prologue = b""

    # Stimulate initialize process => responder.initialize(False, s=self.static_keypair, rs=self.user_static_pk)
    # Generate server's keypair (rs) => .private & .public.
    server_keypair = DH.generate_keypair(server_static_sk) # rs
    # Initialize KHandShake process.
    K_initiator = SymmetricState(CipherState(ChaChaPolyCipher()), SHA512Hash())
    K_initiator.initialize_symmetric(protocol_name.encode()) # self.protocol_name.encode()
    K_initiator.mix_hash(prologue) # prologue
    K_initiator.mix_hash(params.client_static_pk.data) # self.user_static_pk.data
    K_initiator.mix_hash(server_keypair.public.data)  # self.static_keypair.public.data


    # Step 3 : Stimulate write message process.
    # -> e
    # -> es
    # -> ss
    # -> msg

    # -> e : generate attacker's ephemeral keypair (e)
    e = DH.generate_keypair() # self.e = self.dh.generate_keypair()
    K_initiator.mix_hash(e.public.data) # self.symmetricstate.mix_hash(self.e.public.data)

    # -> es : compute "DH(e, rs)" => As server-side to compute "DH(s, e)".
    # s : server_keypair
    # e : attacker_public_key
    es = DH.dh(server_keypair, e.public)
    K_initiator.mix_key(es)

    # -> ss : compute "DH(s, rs)" => As client-side stay the same.
    # s  : server_keypair
    # rs : client_static_public_key
    ss = DH.dh(server_keypair, params.client_static_pk)
    K_initiator.mix_key(ss)

    # -> msg
    payload = bytearray()
    payload.extend(e.public.data)
    payload.extend(K_initiator.encrypt_and_hash(target_data))

    params.update_storage(bytes(payload))

    #pass
