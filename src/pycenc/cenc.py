"""CENC (Common Encryption, ISO/IEC 23001-7) decryption for fragmented MP4.

Implements AES-128-CTR sample decryption for DASH/fragmented MP4 files
encrypted with scheme ``cenc`` (full-sample or subsample). The output is
a clean, muxable MP4 with all CENC boxes stripped and sample-entry types
restored (``encv``->``avc1``, ``enca``->``mp4a``, ...).

This module **does not obtain keys**: it takes a content key as input and
performs standard AES-CTR. There is no CDM, no key exchange, no network.

Limitations of this version:

* Single content key per file (the common case, including all EITB
  content). Multi-key (per-track KID) support is planned.
* Scheme ``cenc`` only. ``cbcs`` (pattern/CBC) and ``cens`` are planned.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .boxes import iter_raw_boxes, parse_one, serialize

# Box types removed from decrypted output.
STRIP = {b'sinf', b'senc', b'saiz', b'saio', b'pssh'}

# Encrypted sample-entry types -> original (clear) format.
ENC_TYPES = {
    b'encv': b'avc1',
    b'enca': b'mp4a',
    b'enct': b'mp4v',
    b'encs': b'mp4s',
}


# --------------------------------------------------------------------------- #
# AES helpers
# --------------------------------------------------------------------------- #

def _ctr(key, iv, ciphertext):
    """AES-128-CTR decrypt.

    A CENC 8-byte IV is the high 8 bytes of the 16-byte counter block; the
    low 8 bytes are a counter starting at 0. ``cryptography``'s CTR mode
    increments the full 128 bits, which is identical for any real sample
    (well under 2^64 blocks), so we pad 8-byte IVs with zeros.
    """
    if len(iv) == 8:
        iv = iv + b'\x00' * 8
    dec = Cipher(algorithms.AES(key), modes.CTR(iv),
                 backend=default_backend()).decryptor()
    return dec.update(ciphertext) + dec.finalize()


# --------------------------------------------------------------------------- #
# senc / trun parsing
# --------------------------------------------------------------------------- #

def _find_senc_bodies(moof_body):
    """Return every ``senc`` box body inside a ``moof`` (recurses into traf)."""
    out = []

    def rec(data):
        for typ, hdr, size, off in iter_raw_boxes(data):
            body = data[off + hdr:off + size]
            if typ == b'senc':
                out.append(body)
            if typ in (b'moof', b'traf'):
                rec(body)

    rec(moof_body)
    return out


def _find_box_bodies(data, want):
    """Return bodies of every ``want`` box inside moof/traf."""
    out = []

    def rec(d):
        for typ, hdr, size, off in iter_raw_boxes(d):
            body = d[off + hdr:off + size]
            if typ == want:
                out.append(body)
            if typ in (b'moof', b'traf'):
                rec(body)

    rec(data)
    return out


def parse_senc(body, iv_size, has_sub):
    """Parse a ``senc`` box body.

    Returns ``(samples, bytes_consumed)`` where each sample is
    ``(iv, [(clear_bytes, cipher_bytes), ...])`` and ``bytes_consumed``
    excludes the 8-byte version+flags+sample_count header.
    """
    n = struct.unpack('>I', body[4:8])[0]
    pos = 8
    samples = []
    for _ in range(n):
        iv = body[pos:pos + iv_size]
        pos += iv_size
        subs = []
        if has_sub:
            nsub = struct.unpack('>H', body[pos:pos + 2])[0]
            pos += 2
            for _ in range(nsub):
                clear = struct.unpack('>H', body[pos:pos + 2])[0]
                pos += 2
                cipher = struct.unpack('>I', body[pos:pos + 4])[0]
                pos += 4
                subs.append((clear, cipher))
        samples.append((iv, subs))
    return samples, pos - 8


def detect_format(body):
    """Auto-detect ``(iv_size, has_subsample)`` for a ``senc`` box.

    Some files (e.g. on EITB's CDN) carry non-compliant ``senc`` flags or
    a ``tenc`` reporting ``per_sample_iv_size=0``. Rather than trust those
    fields, we try interpretations in order of likelihood and pick the
    first that parses cleanly: consumes exactly ``len(body)-8`` bytes with
    sane subsample counts (1..64 per sample).
    """
    n = struct.unpack('>I', body[4:8])[0]
    target = len(body) - 8
    for iv_size, has_sub in [(8, True), (8, False), (16, True), (16, False)]:
        try:
            samples, consumed = parse_senc(body, iv_size, has_sub)
        except (struct.error, IndexError):
            continue
        if consumed != target or len(samples) != n:
            continue
        if has_sub and any(len(s) == 0 or len(s) > 64 for _, s in samples):
            continue
        return iv_size, has_sub
    return 8, False  # last resort


def derive_format(data):
    """Detect ``(iv_size, has_subsample)`` from the first ``senc`` in the file."""
    for b in _find_senc_bodies(data):
        return detect_format(b)
    return 8, False


def parse_trun(body):
    """Return ``(sample_sizes, data_offset)`` from a ``trun`` box body.

    ``data_offset`` is ``None`` when the flag is absent.
    """
    flags = struct.unpack('>I', body[:4])[0] & 0xffffff
    n = struct.unpack('>I', body[4:8])[0]
    pos = 8
    data_offset = None
    if flags & 0x001:  # data_offset_present
        data_offset = struct.unpack('>i', body[pos:pos + 4])[0]
        pos += 4
    if flags & 0x004:  # first_sample_flags_present
        pos += 4
    sizes = []
    for _ in range(n):
        if flags & 0x100:  # sample_duration_present
            pos += 4
        if flags & 0x200:  # sample_size_present
            sizes.append(struct.unpack('>I', body[pos:pos + 4])[0])
            pos += 4
        else:
            sizes.append(0)
        if flags & 0x400:  # sample_flags_present
            pos += 4
        if flags & 0x800:  # sample_composition_time_offset_present
            pos += 4
    return sizes, data_offset


# --------------------------------------------------------------------------- #
# Tree transforms: strip CENC boxes, patch types, fix trun offsets
# --------------------------------------------------------------------------- #

def _frma_type(data):
    """Original format (4 bytes) from the first ``frma`` box, or ``None``."""
    i = data.find(b'frma')
    return data[i + 4:i + 8] if i >= 0 else None


def _strip_and_patch(node, frma):
    """Recursively strip CENC boxes and patch encrypted sample-entry types.

    Returns the number of bytes removed from this node's payload, used to
    fix up ``trun.data_offset`` in the enclosing ``moof``.
    """
    if node.children is None:
        return 0
    new_children = []
    removed = 0
    for c in node.children:
        if c.type in STRIP:
            removed += len(serialize(c))
            continue
        removed += _strip_and_patch(c, frma)
        new_children.append(c)
    if node.type in ENC_TYPES and frma:
        node.type = frma
    node.children = new_children
    return removed


def _fix_trun_offset(node, delta):
    """Subtract ``delta`` from every ``trun.data_offset`` (in place)."""
    if node.children is None:
        if node.type == b'trun' and delta:
            b = bytearray(node.data)
            flags = struct.unpack('>I', b[:4])[0] & 0xffffff
            if flags & 0x001:
                old = struct.unpack('>i', b[8:12])[0]
                b[8:12] = struct.pack('>i', old - delta)
                node.data = bytes(b)
        return
    for c in node.children:
        _fix_trun_offset(c, delta)


# --------------------------------------------------------------------------- #
# Public API
# --------------------------------------------------------------------------- #

def decrypt_bytes(key, data):
    """Decrypt CENC-encrypted fragmented MP4 bytes.

    Args:
        key: 16-byte AES content key.
        data: encrypted fragmented MP4 file as ``bytes``.

    Returns:
        Decrypted MP4 as ``bytes``, with CENC boxes stripped and sample
        entries restored so the result is muxable by ffmpeg / standard
        tools.
    """
    iv_size, has_sub = derive_format(data)
    frma = _frma_type(data)

    out = bytearray()
    pending_senc = None
    pending_sizes = None

    for typ, hdr, size, off in iter_raw_boxes(data):
        body = data[off + hdr:off + size]

        if typ == b'moov':
            tree = parse_one(b'moov', body)
            _strip_and_patch(tree, frma)
            out += serialize(tree)

        elif typ == b'moof':
            sencs = _find_senc_bodies(body)
            pending_senc = sencs[0] if sencs else None
            truns = _find_box_bodies(body, b'trun')
            pending_sizes = parse_trun(truns[0])[0] if truns else []
            tree = parse_one(b'moof', body)
            removed = _strip_and_patch(tree, frma)
            _fix_trun_offset(tree, removed)
            out += serialize(tree)

        elif typ == b'mdat':
            sizes = pending_sizes or []
            samples, _ = (parse_senc(pending_senc, iv_size, has_sub)
                          if pending_senc else ([], 0))
            clear = bytearray()
            pos = 0
            for (iv, subs), sz in zip(samples, sizes):
                if not subs:
                    clear += _ctr(key, iv, body[pos:pos + sz])
                    pos += sz
                else:
                    for cb, eb in subs:
                        clear += body[pos:pos + cb]
                        pos += cb
                        clear += _ctr(key, iv, body[pos:pos + eb])
                        pos += eb
            out += struct.pack('>I', 8 + len(clear)) + b'mdat' + bytes(clear)

        else:
            out += struct.pack('>I', size) + typ + body

    return bytes(out)


def decrypt_file(key, input_file, output_file):
    """Decrypt a CENC-encrypted fragmented MP4 file.

    Args:
        key: 16-byte AES content key.
        input_file: open binary input (readable, ``rb``).
        output_file: open binary output (writable, ``wb``).
    """
    data = input_file.read()
    output_file.write(decrypt_bytes(key, data))
