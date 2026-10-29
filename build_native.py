#!/usr/bin/env python3
"""Build optional Linux x86-64 AVX2 component, then perform a reference self-test."""
import os
import platform
import shutil
import subprocess
from pathlib import Path
def main():
    folder=Path(__file__).resolve().parent
    if platform.system()!="Linux" or platform.machine().lower() not in ("x86_64","amd64"):
        raise SystemExit("Build requires Linux x86-64.")
    if "avx2" not in Path("/proc/cpuinfo").read_text().lower().split():
        raise SystemExit("CPU does not advertise AVX2.")
    compiler=shutil.which(os.environ.get("CC","gcc"))
    if not compiler:
        raise SystemExit("GCC not found. On Ubuntu: sudo apt install build-essential")
    # A new build must be re-benchmarked before recovery can use it.
    folder.joinpath("pbkdf2_backend.json").unlink(missing_ok=True)
    subprocess.run([compiler,"-O3","-mavx2","-fPIC","-shared","-Wall","-Wextra",
                    "-o",str(folder/"libpbkdf2_avx2.so"),
                    str(folder/"pbkdf2_avx2.c")],check=True)
    from pbkdf2_native import NativePBKDF2
    NativePBKDF2()
    print("Build and initial self-test passed. Run benchmark_pbkdf2.py --enable next.")
if __name__=="__main__":
    main()
