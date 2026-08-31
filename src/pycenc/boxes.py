"""Minimal ISO BMFF (MP4) box parser and serializer.

Enough to walk and rebuild fragmented MP4 files for CENC decryption:
container boxes, sample entries (with their variable-length prelude),
and the ``stsd`` entry-count preamble. No external dependencies.
"""
from __future__ import annotations

import struct

# Box types that contain only child boxes (no payload of their own).
CONTAINERS = {
    b'moov', b'trak', b'mdia', b'minf', b'stbl', b'stsd',
    b'sinf', b'schi', b'moof', b'traf', b'mvex', b'edts',
    b'dinf', b'mfra',
}

# Sample-entry types: they carry a variable-length prelude
# (6 reserved + 2 data_ref_index + codec-specific fields) followed by
# child boxes.
SAMPLE_ENTRY = {
    b'encv', b'enca', b'enct', b'encs',
    b'avc1', b'avc3', b'mp4v', b'hev1', b'hvc1',
    b'mp4a', b'ac-3', b'ec-3', b'opus', b'mjpa', b'mjpg',
}

# Child box types that may appear inside a sample entry. Used to locate
# the end of the variable-length prelude when splitting the body.
SE_CHILDREN = {
    b'sinf', b'esds', b'avcC', b'hvcC', b'colr', b'btrt',
    b'pasp', b'clap', b'tapt', b'uuid', b'wave', b'samr',
    b'sawb', b'dac3', b'ddec', b'dops', b'txtC',
}


class Box:
    """An ISO BMFF box node.

    A node is exactly one of:

    * a **leaf** (``data`` set, ``children`` is ``None``),
    * a **container** (``children`` is a list, ``data`` is ``None``),
    * a **sample entry** (``prelude`` + ``children``),
    * an **stsd** box (``extra`` holds version+flags+entry_count, plus
      ``children``).

    Sizes are recomputed on serialization; 64-bit sizes are emitted
    automatically when a box exceeds 4 GiB.
    """
    __slots__ = ('type', 'data', 'children', 'prelude', 'extra')

    def __init__(self, type, data=None, children=None, prelude=b'', extra=b''):
        self.type = type
        self.data = data
        self.children = children
        self.prelude = prelude
        self.extra = extra

    @property
    def is_container(self) -> bool:
        return self.children is not None

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        t = self.type.decode('latin1') if isinstance(self.type, bytes) else self.type
        n = len(self.children) if self.children is not None else '-'
        return f"<Box {t} children={n}>"


def parse_boxes(data, off=0, end=None):
    """Parse a sequence of sibling boxes into :class:`Box` nodes."""
    if end is None:
        end = len(data)
    out = []
    while off + 8 <= end:
        size = struct.unpack('>I', data[off:off + 4])[0]
        typ = data[off + 4:off + 8]
        hdr = 8
        if size == 1:  # 64-bit extended size
            size = struct.unpack('>Q', data[off + 8:off + 16])[0]
            hdr = 16
        elif size == 0:  # box extends to end of container
            size = end - off
        if size < hdr or off + size > end:
            break
        body = data[off + hdr:off + size]
        out.append(parse_one(typ, body))
        off += size
    return out


def parse_one(typ, body):
    """Parse a single box body into a :class:`Box` (dispatching by type)."""
    if typ == b'stsd':
        return Box(typ, children=parse_boxes(body[8:]), extra=body[:8])
    if typ in CONTAINERS:
        return Box(typ, children=parse_boxes(body))
    if typ in SAMPLE_ENTRY:
        prelude, children = _split_sample_entry(body)
        return Box(typ, children=children, prelude=prelude)
    return Box(typ, data=body)


def _split_sample_entry(body):
    """Split a sample-entry body into ``(prelude, children)``.

    The prelude is everything before the first recognised child box:
    6 reserved bytes + 2 data_ref_index + codec-specific fields. We scan
    forward one byte at a time until a plausible child box (recognised
    type, sane size) appears.
    """
    n = len(body)
    i = 8  # skip the 8-byte sample-entry base
    while i + 8 <= n:
        size = struct.unpack('>I', body[i:i + 4])[0]
        ctyp = body[i + 4:i + 8]
        if 8 <= size <= n - i and ctyp in SE_CHILDREN:
            return body[:i], parse_boxes(body[i:])
        i += 1
    return body, []


def serialize(box):
    """Serialize a :class:`Box` back to bytes (recomputes sizes)."""
    if box.children is None:
        payload = box.data
    else:
        payload = box.extra + (box.prelude or b'')
        for c in box.children:
            payload += serialize(c)
    size = 8 + len(payload)
    if size >= 0x100000000:  # need 64-bit extended size
        return (struct.pack('>I', 1) + box.type
                + struct.pack('>Q', 16 + len(payload)) + payload)
    return struct.pack('>I', size) + box.type + payload


def iter_raw_boxes(data, off=0, end=None):
    """Yield ``(type, header_size, size, offset)`` for sibling boxes in a
    byte string, without building a tree. Useful for cheap scans."""
    if end is None:
        end = len(data)
    while off + 8 <= end:
        size = struct.unpack('>I', data[off:off + 4])[0]
        typ = data[off + 4:off + 8]
        hdr = 8
        if size == 1:
            size = struct.unpack('>Q', data[off + 8:off + 16])[0]
            hdr = 16
        elif size == 0:
            size = end - off
        if size < hdr or off + size > end:
            return
        yield typ, hdr, size, off
        off += size
