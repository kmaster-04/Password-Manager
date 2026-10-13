import os
import numpy as np
from reedsolo import RSCodec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

N_STABLE_DIMENSIONS = 112
ECC_SYMBOLS = 8
HKDF_INFO = b"biometric-fuzzy-extractor-v1"


class BiometricFuzzyExtractor:
    def __init__(self, n_dims=N_STABLE_DIMENSIONS, ecc_symbols=ECC_SYMBOLS):
        self.n_dims = n_dims
        self.n_bytes = (n_dims + 7) // 8
        self.ecc_symbols = ecc_symbols
        self.rs = RSCodec(ecc_symbols)

    def identify_stable_dimensions(self, encodings):
        arr = np.array(encodings)
        stds = np.std(arr, axis=0)
        return np.argsort(stds)[:self.n_dims]

    def _extract_bytes(self, encoding, indices):
        signs = (encoding[indices] >= 0).astype(np.uint8)
        padding = (-len(signs)) % 8
        padded = np.concatenate([signs, np.zeros(padding, dtype=np.uint8)])
        return np.packbits(padded).tobytes()

    def _derive_key(self, message):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=HKDF_INFO,
        )
        return hkdf.derive(message)

    def enroll(self, encodings):
        indices = self.identify_stable_dimensions(encodings)
        mean_encoding = np.mean(encodings, axis=0)
        B = self._extract_bytes(mean_encoding, indices)

        R = os.urandom(len(B))
        S = bytes(a ^ b for a, b in zip(B, R))
        codeword = self.rs.encode(R)
        P = codeword[len(R):]

        key = self._derive_key(B)

        return {
            "indices": indices.tolist(),
            "sketch": S.hex(),
            "parity": P.hex(),
            "message_len": len(B),
        }, key

    def reconstruct(self, live_encoding, enrollment, verbose=False):
        indices = np.array(enrollment["indices"])
        S = bytes.fromhex(enrollment["sketch"])
        P = bytes.fromhex(enrollment["parity"])
        msg_len = enrollment["message_len"]

        B_prime = self._extract_bytes(live_encoding, indices)
        R_prime = bytes(a ^ b for a, b in zip(B_prime, S))

        codeword_prime = R_prime + P
        try:
            result = self.rs.decode(codeword_prime)
            if isinstance(result, tuple):
                R = bytes(result[0])[:msg_len]
            else:
                R = bytes(result)[:msg_len]
        except Exception as e:
            if verbose:
                print(f"Reed-Solomon decode failed: {e}")
            return None

        B = bytes(a ^ b for a, b in zip(R, S))
        return self._derive_key(B)