"""Unit tests for pycenc.

These tests use synthetic data only (no copyrighted fixtures) and validate
the primitives: AES-CTR round-trip, senc parsing, format auto-detection,
and box parse/serialize round-trips.

Real-content integration tests run when the ``PYCENC_FIXTURE_DIR``
environment variable points at a directory containing encrypted files +
a ``keys.json`` mapping ``{filename: {"key": hex, "ref": "ref_filename"}}``.
"""
import os
import struct
import tempfile

import pytest

from pycenc import decrypt_bytes, decrypt_file, decrypt_stream
from pycenc.boxes import iter_raw_boxes, parse_boxes, parse_one, serialize, Box
from pycenc.cenc import (
    _ctr,
    detect_format,
    parse_senc,
    parse_trun,
    derive_format,
)


# --------------------------------------------------------------------------- #
# AES-CTR
# --------------------------------------------------------------------------- #

def test_ctr_roundtrip():
    key = b"\x00" * 16
    iv = b"\x11" * 8
    plaintext = b"the quick brown fox " * 50
    # CTR mode: encrypt and decrypt are the same operation.
    ciphertext = _ctr(key, iv, plaintext)
    assert ciphertext != plaintext
    assert _ctr(key, iv, ciphertext) == plaintext


def test_ctr_eight_byte_iv_matches_padded():
    key = b"\xab" * 16
    iv8 = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    iv16 = iv8 + b"\x00" * 8
    data = b"streaming segment payload" * 8
    assert _ctr(key, iv8, data) == _ctr(key, iv16, data)


# --------------------------------------------------------------------------- #
# senc parsing & format detection
# --------------------------------------------------------------------------- #

def _build_senc(iv_size, has_sub, samples):
    """Build a synthetic senc box body. samples: [(iv, [(clear, cipher), ...])]."""
    flags = 1 if has_sub else 0
    out = struct.pack(">I", flags)            # version(0) + flags
    out += struct.pack(">I", len(samples))
    for iv, subs in samples:
        out += iv
        if has_sub:
            out += struct.pack(">H", len(subs))
            for clear, cipher in subs:
                out += struct.pack(">HI", clear, cipher)
    return out


def test_parse_senc_no_subsample():
    body = _build_senc(16, False, [(b"\x00" * 16, []), (b"\x01" * 16, [])])
    samples, consumed = parse_senc(body, 16, False)
    assert len(samples) == 2
    assert samples[0][0] == b"\x00" * 16
    assert samples[1][0] == b"\x01" * 16
    assert all(s == [] for _, s in samples)
    assert consumed == 32


def test_parse_senc_subsample():
    body = _build_senc(8, True, [(b"\x00" * 8, [(2, 16), (4, 32)])])
    samples, _ = parse_senc(body, 8, True)
    assert samples[0][1] == [(2, 16), (4, 32)]


def test_detect_format_no_subsample_16byte():
    body = _build_senc(16, False, [(b"\x00" * 16, []), (b"\x01" * 16, [])])
    assert detect_format(body) == (16, False)


def test_detect_format_subsample_8byte():
    body = _build_senc(8, True, [(b"\x00" * 8, [(2, 16)]), (b"\x01" * 8, [(2, 16)])])
    assert detect_format(body) == (8, True)


def test_detect_format_no_subsample_8byte():
    body = _build_senc(8, False, [(b"\x00" * 8, []), (b"\x01" * 8, [])])
    assert detect_format(body) == (8, False)


def test_detect_format_rejects_garbage():
    # A 16-byte-IV no-subsample body must NOT be misread as 8-byte+subsample:
    # the "subsample count" would be random bytes from the next IV, likely >64.
    body = _build_senc(16, False, [(b"\xff" * 16, []), (b"\xff" * 16, [])])
    assert detect_format(body) == (16, False)


# --------------------------------------------------------------------------- #
# trun parsing
# --------------------------------------------------------------------------- #

def test_parse_trun_sizes_and_offset():
    # flags = data_offset(0x1) | sample_size(0x200); 3 samples; data_offset=1000
    flags = 0x201
    body = struct.pack(">I", flags)
    body += struct.pack(">I", 3)              # sample_count
    body += struct.pack(">i", 1000)           # data_offset
    body += struct.pack(">III", 10, 20, 30)   # sample sizes
    sizes, off = parse_trun(body)
    assert sizes == [10, 20, 30]
    assert off == 1000


def test_parse_trun_no_offset():
    flags = 0x200  # sample_size only
    body = struct.pack(">I", flags) + struct.pack(">I", 2)
    body += struct.pack(">II", 5, 7)
    sizes, off = parse_trun(body)
    assert sizes == [5, 7]
    assert off is None


# --------------------------------------------------------------------------- #
# box parse/serialize round-trip
# --------------------------------------------------------------------------- #

def test_box_roundtrip_leaf():
    leaf = Box(b"ftyp", data=b"isom\x00\x00\x02\x00isomiso2")
    data = serialize(leaf)
    typ, hdr, size, off = next(iter_raw_boxes(data))
    assert typ == b"ftyp"
    assert size == len(data)
    parsed = parse_boxes(data)[0]
    assert parsed.type == b"ftyp"
    assert parsed.data == leaf.data


def test_box_roundtrip_container():
    inner = Box(b"mvhd", data=b"\x00" * 100)
    outer = Box(b"moov", children=[inner])
    data = serialize(outer)
    parsed = parse_boxes(data)[0]
    assert parsed.type == b"moov"
    assert len(parsed.children) == 1
    assert parsed.children[0].type == b"mvhd"
    assert parsed.children[0].data == b"\x00" * 100


def test_box_roundtrip_preserves_size():
    leaf = Box(b"free", data=b"x" * 1000)
    data = serialize(leaf)
    assert struct.unpack(">I", data[:4])[0] == 1008  # 8 header + 1000


# --------------------------------------------------------------------------- #
# End-to-end: encrypt-then-decrypt a synthetic fragmented MP4
# --------------------------------------------------------------------------- #

def _build_synthetic_fragmented_mp4(key, plaintext_samples):
    """Build a minimal cenc-encrypted fragmented MP4 with one moof+mdat.

    Uses 8-byte IVs, no subsample encryption. Returns (mp4_bytes, ivs).
    Encryption is AES-CTR (same op as decryption).
    """
    ivs = [bytes([i, 0, 0, 0, 0, 0, 0, 0]) for i in range(len(plaintext_samples))]
    ciphertexts = [_ctr(key, iv, pt) for iv, pt in zip(ivs, plaintext_samples)]
    mdat_payload = b"".join(ciphertexts)
    sizes = [len(c) for c in ciphertexts]

    # senc box: version=0, flags=0 (no subsample), count, then IVs
    senc = struct.pack(">II", 0, len(ivs)) + b"".join(ivs)
    senc_box = struct.pack(">I", 8 + len(senc)) + b"senc" + senc

    # trun box: flags=0x201 (data_offset + sample_size), count, offset=0, sizes
    trun_body = struct.pack(">II", 0x201, len(sizes)) + struct.pack(">i", 0)
    trun_body += b"".join(struct.pack(">I", s) for s in sizes)
    trun_box = struct.pack(">I", 8 + len(trun_body)) + b"trun" + trun_body

    # tfhd + traf + mfhd + moof
    tfhd_body = struct.pack(">II", 0, 0)  # version+flags=0, track_id=0
    tfhd_box = struct.pack(">I", 8 + len(tfhd_body)) + b"tfhd" + tfhd_body
    traf_body = tfhd_box + trun_box + senc_box
    traf_box = struct.pack(">I", 8 + len(traf_body)) + b"traf" + traf_body
    mfhd_body = struct.pack(">II", 0, 1)  # sequence_number=1
    mfhd_box = struct.pack(">I", 8 + len(mfhd_body)) + b"mfhd" + mfhd_body
    moof_body = mfhd_box + traf_box
    moof_box = struct.pack(">I", 8 + len(moof_body)) + b"moof" + moof_body

    mdat_box = struct.pack(">I", 8 + len(mdat_payload)) + b"mdat" + mdat_payload

    # minimal moov with a frma box (so _frma_type finds 'mp4a')
    frma_box = struct.pack(">I", 12) + b"frma" + b"mp4a"
    stsd_body = struct.pack(">I", 0) + struct.pack(">I", 0)  # v+f + count=0
    stsd_box = struct.pack(">I", 8 + len(stsd_body)) + b"stsd" + stsd_body
    moov_body = stsd_box + frma_box
    moov_box = struct.pack(">I", 8 + len(moov_body)) + b"moov" + moov_body

    return moov_box + moof_box + mdat_box, ivs


def test_decrypt_synthetic_fragmented_mp4():
    key = b"\x42" * 16
    plaintexts = [b"first sample payload" * 4,
                  b"second sample payload" * 3,
                  b"third" * 20]
    mp4, _ = _build_synthetic_fragmented_mp4(key, plaintexts)
    clear = decrypt_bytes(key, mp4)
    # the decrypted mdat should concatenate the original plaintexts
    expected = b"".join(plaintexts)
    for typ, hdr, size, off in iter_raw_boxes(clear):
        if typ == b"mdat":
            assert clear[off + hdr:off + size] == expected
            return
    pytest.fail("no mdat in output")


def test_decrypt_file_round_trip(tmp_path):
    key = b"\x07" * 16
    plaintexts = [b"hello world " * 10]
    mp4, _ = _build_synthetic_fragmented_mp4(key, plaintexts)
    inp = tmp_path / "enc.mp4"
    out = tmp_path / "dec.mp4"
    inp.write_bytes(mp4)
    with open(inp, "rb") as fi, open(out, "wb") as fo:
        decrypt_file(key, fi, fo)
    clear = out.read_bytes()
    for typ, hdr, size, off in iter_raw_boxes(clear):
        if typ == b"mdat":
            assert clear[off + hdr:off + size] == b"".join(plaintexts)
            return
    pytest.fail("no mdat in output")


# --------------------------------------------------------------------------- #
# Streaming decryption
# --------------------------------------------------------------------------- #

class _SlowStream:
    """A read() that returns at most `chunk` bytes per call, to simulate a
    pipe that yields partial reads. Stresses _read_exact."""
    def __init__(self, data, chunk=1):
        self._data = data
        self._pos = 0
        self._chunk = chunk
    def read(self, n=-1):
        if self._pos >= len(self._data):
            return b""
        if n is None or n < 0:
            n = len(self._data) - self._pos
        n = min(n, self._chunk)
        chunk = self._data[self._pos:self._pos + n]
        self._pos += n
        return chunk


def test_stream_matches_bytes():
    """Streaming output must be byte-identical to the batch output."""
    import io
    key = b"\x55" * 16
    plaintexts = [b"alpha sample " * 5, b"beta " * 40, b"gamma" * 10]
    mp4, _ = _build_synthetic_fragmented_mp4(key, plaintexts)
    batch = decrypt_bytes(key, mp4)
    out = io.BytesIO()
    decrypt_stream(key, io.BytesIO(mp4), out)
    assert out.getvalue() == batch


def test_stream_with_partial_reads():
    """Streaming must work when read() returns one byte at a time."""
    import io
    key = b"\x99" * 16
    plaintexts = [b"streaming segment payload " * 4, b"second fragment" * 8]
    mp4, _ = _build_synthetic_fragmented_mp4(key, plaintexts)
    out = io.BytesIO()
    decrypt_stream(key, _SlowStream(mp4, chunk=1), out)
    # verify the decrypted mdat matches the original plaintexts
    clear = out.getvalue()
    for typ, hdr, size, off in iter_raw_boxes(clear):
        if typ == b"mdat":
            assert clear[off + hdr:off + size] == b"".join(plaintexts)
            return
    pytest.fail("no mdat in output")


def test_stream_produces_no_whole_file_buffer():
    """Streaming should not need to buffer the whole input — verify it works
    even when the output is read incrementally (no seek needed)."""
    import io
    key = b"\x33" * 16
    plaintexts = [b"x" * 5000, b"y" * 3000]  # multi-sample, multi-fragment-ish
    mp4, _ = _build_synthetic_fragmented_mp4(key, plaintexts)
    instream = _SlowStream(mp4, chunk=7)  # awkward chunk size
    outstream = io.BytesIO()
    decrypt_stream(key, instream, outstream)
    # sanity: output has an mdat with the concatenated plaintext
    clear = outstream.getvalue()
    mdats = [clear[off + hdr:off + size]
             for typ, hdr, size, off in iter_raw_boxes(clear) if typ == b"mdat"]
    assert b"".join(mdats) == b"".join(plaintexts)


# --------------------------------------------------------------------------- #
# Real-content integration (opt-in, no fixtures shipped)
# --------------------------------------------------------------------------- #

@pytest.mark.skipif(not os.environ.get("PYCENC_FIXTURE_DIR"),
                    reason="set PYCENC_FIXTURE_DIR to run real-content tests")
def test_real_content_matches_reference():
    import json
    d = os.environ["PYCENC_FIXTURE_DIR"]
    manifest = json.load(open(os.path.join(d, "keys.json")))
    for fname, spec in manifest.items():
        enc = open(os.path.join(d, fname), "rb").read()
        key = bytes.fromhex(spec["key"].split(":")[-1])
        ref = open(os.path.join(d, spec["ref"]), "rb").read()
        # compare decrypted mdat payloads
        def mdats(b):
            out = bytearray()
            for t, h, s, o in iter_raw_boxes(b):
                if t == b"mdat":
                    out += b[o + h:o + s]
            return bytes(out)
        assert mdats(decrypt_bytes(key, enc)) == mdats(ref), fname
