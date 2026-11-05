import tenseal as ts
import threading
import tenseal.sealapi  # Register SEAL Modulus bindings used for parameter validation.
from .crypto_engine import pack, unpack


class PIRServer:
    def __init__(self, dataset):
        self.dataset = dataset
        self.columns = list(map(list, zip(*dataset.matrix)))
        self.evaluations = 0
        self.lock = threading.RLock()

    def repartition(self, page_size, version):
        from .dataset_manager import DatasetManager
        from .transport import SnapshotChanged
        if type(page_size) is not int or not 1 <= page_size <= 1024:
            raise ValueError('page size must be an integer from 1 to 1024')
        with self.lock:
            if version != self.dataset.manifest['version']:
                raise SnapshotChanged('snapshot changed; refresh before repartitioning')
            old = self.dataset
            rebuilt = DatasetManager([r for page in old.pages for r in page],
                page_size=page_size, seed=old.seed, created_at=old.created_at)
            columns = list(map(list, zip(*rebuilt.matrix)))
            self.dataset, self.columns = rebuilt, columns
            return rebuilt.manifest

    @staticmethod
    def load_context(blob):
        context = ts.context_from(blob, n_threads=1)
        if context.has_secret_key():
            raise ValueError('server refuses secret key material')
        if not context.has_galois_keys():
            raise ValueError('rotation keys required')
        data = context.seal_context().data.first_context_data()
        parms = data.parms()
        from .crypto_engine import PLAIN_MODULUS
        if int(parms.scheme()) != int(ts.sealapi.SCHEME_TYPE.BFV):
            raise ValueError('BFV scheme required')
        if parms.poly_modulus_degree() != 8192 or parms.plain_modulus().value() != PLAIN_MODULUS:
            raise ValueError('unsupported BFV parameters')
        return context

    def evaluate(self, frame, context):
        with self.lock:
            return self._evaluate(frame, context)

    def _evaluate(self, frame, context):
        query = ts.bfv_vector_from(context, unpack(frame))
        if query.size() != len(self.dataset.pages):
            raise ValueError('query dimension mismatch')
        # Every column and page participates, independently of selected index.
        response = b''.join(pack(query.dot(column).serialize()) for column in self.columns)
        self.evaluations += 1
        return response
