"""pycenc — pure-Python CENC (Common Encryption) decryptor for fragmented MP4.

Implements AES-128-CTR sample decryption for ``cenc``-encrypted DASH/MP4
files, given a content key. No CDM, no key exchange, no network — just
standard crypto on a published standard (ISO/IEC 23001-7).

Example::

    from pycenc import decrypt_bytes
    clear = decrypt_bytes(key, encrypted_mp4_bytes)

Or from the command line::

    pycenc --key 662f4a9a18714d378d0cd58adcc62b16:3adcf39a811a5ab45f901e5b835b688c \\
           input.m4s output.mp4
"""
from __future__ import annotations

__version__ = "0.2.0"

from .cenc import decrypt_bytes, decrypt_file, decrypt_stream

__all__ = ["decrypt_bytes", "decrypt_file", "decrypt_stream", "__version__"]
