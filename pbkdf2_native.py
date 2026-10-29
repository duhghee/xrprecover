"""Optional four-lane AVX2 BIP39 engine, empty passphrase, <=128 UTF8 bytes."""
import ctypes
import hashlib
import platform
import unicodedata
from pathlib import Path

class NativePBKDF2:
    def __init__(self, path=None):
        if platform.system() != "Linux" or platform.machine().lower() not in ("x86_64", "amd64"):
            raise RuntimeError("This build supports Linux x86-64 with AVX2")
        try:
            flags = Path("/proc/cpuinfo").read_text().lower()
        except OSError as error:
            raise RuntimeError("Cannot verify CPU AVX2 support") from error
        if "avx2" not in flags.split():
            raise RuntimeError("CPU does not advertise AVX2")
        path = Path(path) if path else Path(__file__).with_name("libpbkdf2_avx2.so")
        self.lib = ctypes.CDLL(str(path.resolve()))
        self.fn = self.lib.pbkdf2_bip39_batch
        self.fn.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                           ctypes.c_void_p, ctypes.c_size_t]
        self.fn.restype = ctypes.c_int
        # Fail closed on any mismatch before using this library.
        samples = ["abandon " * 11 + "about", "", "x" * 128, "é test"]
        if self.derive(samples) != [self.reference(p) for p in samples]:
            raise RuntimeError("Native PBKDF2 self-test failed")

    @staticmethod
    def reference(phrase):
        phrase = unicodedata.normalize("NFKD", phrase).encode("utf8")
        return hashlib.pbkdf2_hmac("sha512", phrase, b"mnemonic", 2048, dklen=64)

    def derive(self, phrases):
        if not phrases:
            return []
        encoded = [unicodedata.normalize("NFKD", p).encode("utf8") for p in phrases]
        # General long inputs retain correct scalar HMAC key hashing.
        if any(len(p) > 128 for p in encoded):
            return [self.reference(p) for p in phrases]
        raw = b"".join(p.ljust(128, b"\0") for p in encoded)
        lengths = (ctypes.c_uint32 * len(encoded))(*(len(p) for p in encoded))
        output = ctypes.create_string_buffer(len(encoded) * 64)
        status = self.fn(raw, lengths, output, len(encoded))
        if status:
            raise RuntimeError(f"Native PBKDF2 returned {status}")
        data = output.raw
        return [data[i:i+64] for i in range(0, len(data), 64)]
