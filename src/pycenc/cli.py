"""Command-line interface.

Examples::

    pycenc --key KID:KEY input.m4s output.mp4        # file -> file
    pycenc --key KID:KEY - -                          # stdin -> stdout (stream)
    pycenc --stream --key KID:KEY                     # stdin -> stdout (stream)

Mirrors the common ``mp4decrypt`` invocation so it can be used as a
drop-in for single-key CENC content, while also supporting streaming
pipes (for live pipelines: yt-dlp | pycenc | ffmpeg | vlc).
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
    p.add_argument('--stream', action='store_true',
                   help="Stream mode: read stdin, write stdout "
                        "(shorthand for input='-' output='-').")
    p.add_argument('input', nargs='?', default=None,
                   help="Encrypted fragmented MP4 input path "
                        "('-' or omitted with --stream for stdin)")
    p.add_argument('output', nargs='?', default=None,
                   help="Decrypted MP4 output path "
                        "('-' or omitted with --stream for stdout)")
    args = p.parse_args(argv)

    if args.stream:
        args.input = args.input or '-'
        args.output = args.output or '-'
    if args.input is None or args.output is None:
        p.error("the following arguments are required: input output "
                "(or use --stream for stdin/stdout)")

    keys = [_parse_key(k) for k in args.key]
    if len(keys) > 1:
        print("warning: multiple keys given; multi-key support is not yet "
              "implemented. Using the first key.", file=sys.stderr)
    key = keys[0]

    # Open input.
    if args.input == '-':
        f_in = sys.stdin.buffer
        close_in = False
    else:
        f_in = open(args.input, 'rb')
        close_in = True

    # Open output.
    if args.output == '-':
        f_out = sys.stdout.buffer
        close_out = False
    else:
        f_out = open(args.output, 'wb')
        close_out = True

    try:
        decrypt_file(key, f_in, f_out)
    except BrokenPipeError:
        # Downstream consumer closed the pipe (e.g. player exited).
        # Exit quietly.
        try:
            sys.stderr.close()
        except Exception:
            pass
    finally:
        if close_in:
            f_in.close()
        if close_out:
            f_out.close()
        else:
            f_out.flush()

    if not args.stream and args.output != '-':
        print(f"wrote {args.output}")


if __name__ == '__main__':
    main()
