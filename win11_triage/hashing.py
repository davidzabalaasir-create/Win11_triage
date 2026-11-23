"""SHA-256 de ficheros con caché persistente y cálculo en paralelo.

Entre análisis la mayoría de ejecutables no cambian: si la ruta, el tamaño y la fecha de modificación
coinciden con la caché (``hash_cache.json``), no se vuelve a leer el fichero. Los que sí hay que leer
se calculan en varios hilos (hashlib libera el GIL con bloques grandes).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

log = logging.getLogger(__name__)

WORKERS = 4
MAX_ENTRIES = 20000
_CHUNK = 1 << 20


def _digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


class HashCache:
    def __init__(self, file: Path | None = None) -> None:
        self.file = file
        self.lock = threading.Lock()
        self.data: dict[str, list] = {}
        self.hits = self.misses = 0
        self._dirty = False
        if file and file.exists():
            try:
                raw = json.loads(file.read_text(encoding="utf-8"))
                self.data = {k: v for k, v in raw.items() if isinstance(v, list) and len(v) == 3}
            except (OSError, ValueError, AttributeError) as e:
                log.warning("hash_cache.json ilegible, se ignora: %s", e)

    def sha256(self, path: str | Path) -> str:
        p = Path(path)
        try:
            st = p.stat()
        except OSError:
            return ""
        key = os.path.normcase(str(p))
        sig = [st.st_size, st.st_mtime_ns]
        with self.lock:
            hit = self.data.get(key)
        if hit and hit[:2] == sig:
            self.hits += 1
            return hit[2]
        try:
            value = _digest(p)
        except OSError:
            return ""
        with self.lock:
            self.misses += 1
            self.data[key] = [*sig, value]
            self._dirty = True
        return value

    def many(self, paths: Iterable[str | Path]) -> dict[str, str]:
        """Hashes de varias rutas a la vez (sin repetir rutas)."""
        unique = list(dict.fromkeys(str(p) for p in paths if p))
        if len(unique) <= 1:
            return {p: self.sha256(p) for p in unique}
        with ThreadPoolExecutor(max_workers=WORKERS, thread_name_prefix="hash") as pool:
            return dict(zip(unique, pool.map(self.sha256, unique), strict=True))

    def save(self) -> None:
        if not (self.file and self._dirty):
            return
        with self.lock:
            items = list(self.data.items())[-MAX_ENTRIES:]
        try:
            tmp = self.file.with_suffix(".tmp")
            tmp.write_text(json.dumps(dict(items)), encoding="utf-8")
            tmp.replace(self.file)
            self._dirty = False
        except OSError as e:
            log.warning("No se pudo guardar la caché de hashes: %s", e)


_active = HashCache()  # sin fichero: solo en memoria (pruebas, dry-run)


def use(cache: HashCache) -> HashCache:
    """Activa la caché para este análisis y devuelve la anterior."""
    global _active
    prev, _active = _active, cache
    return prev


def active() -> HashCache:
    return _active
