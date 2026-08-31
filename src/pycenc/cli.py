"""Command-line interface: ``pycenc --key KID:KEY input.mp4 output.mp4``.

Mirrors the common ``mp4decrypt`` invocation so it can be used as a
drop-in for single-key CENC content.
"""
from __future__ import annotations

import argparse
import binascii
import sys

from .cenc import decrypt_file
from . import __version__


def _parse_key(s):
    """Accept ``KID:KEY`` or bare ``KEY`` (hex); return 16-byte key bytes.

    The KID is informational for CENC decryption (the same key decrypts
    every sample), so only the KEY half is used.
    """
    s = s.strip()
    if ':' in s:
        s = s.split(':', 1)[1]
    try:
        key = binascii.unhexlify(s)
    except binascii.Error as exc:
        raise SystemExit(f"error: key is not valid hex: {exc}")
    if len(key) != 16:
        raise SystemExit(
            f"error: key must be 16 bytes (32 hex chars), got {len(key)}")
    return key


def main(argv=None):
    p = argparse.ArgumentParser(
        prog='pycenc',
        description=('Pure-Python CENC (AES-128-CTR) decryptor for '
                     'fragmented MP4. Takes a content key as input; does '
                     'not obtain keys (no CDM, no network).'))
    p.add_argument('-k', '--key', action='append', required=True,
                   metavar='KID:KEY',
                   help="Content key as 'KID:KEY' or 'KEY' (hex). "
                        "Repeatable; currently a single key is used.")
    p.add_argument('-V', '--version', action='version',
                   version=f'pycenc {__version__}')
    p.add_argument('input', help='Encrypted fragmented MP4 input path')
    p.add_argument('output', help='Decrypted MP4 output path')
    args = p.parse_args(argv)

    keys = [_parse_key(k) for k in args.key]
    if len(keys) > 1:
        print("warning: multiple keys given; multi-key support is not yet "
              "implemented. Using the first key.", file=sys.stderr)
    key = keys[0]

    with open(args.input, 'rb') as f_in, open(args.output, 'wb') as f_out:
        decrypt_file(key, f_in, f_out)
    print(f"wrote {args.output}")


if __name__ == '__main__':
    main()
