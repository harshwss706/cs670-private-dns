"""Real TenSEAL BFV. No plaintext/mock cryptographic backend."""
import struct
import tenseal as ts

PLAIN_MODULUS = 4295049217
FRAME_BYTES = 524288


def pack(blob):
    if len(blob) > FRAME_BYTES - 4:
        raise ValueError('ciphertext exceeds fixed frame')
    return struct.pack('!I', len(blob)) + blob + bytes(FRAME_BYTES - 4 - len(blob))


def unpack(frame):
    if len(frame) != FRAME_BYTES:
        raise ValueError('invalid frame size')
    size, = struct.unpack('!I', frame[:4])
    if not 0 < size <= FRAME_BYTES - 4 or any(frame[4+size:]):
        raise ValueError('invalid frame encoding')
    return frame[4:4+size]


class CryptoEngine:
    def __init__(self):
        self.context = ts.context(ts.SCHEME_TYPE.BFV, poly_modulus_degree=8192,
                                  plain_modulus=PLAIN_MODULUS, n_threads=1)
        self.context.generate_galois_keys()

    def public_context(self):
        return self.context.serialize(save_secret_key=False, save_galois_keys=True,
                                      save_relin_keys=False)

    def query(self, page, count):
        if not 0 <= page < count <= 8192:
            raise ValueError('invalid page index or count')
        values = [0] * count
        values[page] = 1
        return pack(ts.bfv_vector(self.context, values).serialize())

    def decrypt(self, response, width):
        if len(response) != width * FRAME_BYTES:
            raise ValueError('invalid response size')
        return [ts.bfv_vector_from(self.context, unpack(response[i*FRAME_BYTES:(i+1)*FRAME_BYTES]))
                .decrypt()[0] % PLAIN_MODULUS for i in range(width)]
