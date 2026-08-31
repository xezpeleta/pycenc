# pycenc

**Pure-Python CENC (Common Encryption) decryptor for fragmented MP4.**

`pycenc` decrypts `cenc`-encrypted DASH/fragmented MP4 files (the scheme used by Widevine, PlayReady, and ClearKey) using a content key you already have. It is a pure-Python alternative to Bento4's `mp4decrypt` — no compiled dependencies, just the [`cryptography`](https://cryptography.io/) library.

> **What this is:** an implementation of [ISO/IEC 23001-7 (CENC)](https://www.iso.org/standard/68042.html) — a published standard for common encryption of fragmented MP4. It performs standard AES-128-CTR decryption given a content key.
>
> **What this is not:** it does **not** obtain keys. There is no CDM, no key exchange, no license server, no network access. You supply the key; the library does the crypto. (Obtaining keys from a DRM system is a separate concern this library does not address.)

## Install

```bash
pip install pycenc
# or, from source:
uv tool install .   # or: pip install .
```

## CLI

```bash
# file -> file (mp4decrypt-style)
pycenc --key KID:KEY input.m4s output.mp4

# streaming: stdin -> stdout (for live pipelines)
producer | pycenc --stream --key KID:KEY | consumer
# equivalent:
pycenc --key KID:KEY - -
```

Because decryption is a streaming transform with bounded memory, `pycenc`
fits directly into a pipeline: `yt-dlp | pycenc --stream | ffmpeg | vlc`.
The output begins before the input is fully downloaded.

## Library

```python
from pycenc import decrypt_bytes, decrypt_file, decrypt_stream

# in-memory (whole file)
with open("encrypted.m4s", "rb") as f:
    data = f.read()
clear = decrypt_bytes(key_bytes, data)          # -> bytes

# file-based
with open("encrypted.m4s", "rb") as fi, open("decrypted.mp4", "wb") as fo:
    decrypt_file(key_bytes, fi, fo)

# streaming (bounded memory; stdin/stdout, pipes, live pipelines)
decrypt_stream(key_bytes, input_stream, output_stream)
```

`key_bytes` is a 16-byte AES-128 content key.

## How it works

1. Walks the ISO BMFF box tree (`moov`/`trak`/`moof`/`traf`/`mdat`) without external parsers.
2. For each fragment, reads the `senc` box (per-sample IVs + subsample split) and the `trun` box (sample sizes), then decrypts each sample's encrypted bytes with **AES-128-CTR**.
3. **Auto-detects** the IV size (8 or 16 bytes) and whether subsample encryption is used — some files in the wild carry non-compliant `senc` flags or `tenc` reporting `per_sample_iv_size=0`, so detection validates each interpretation against the box length rather than trusting the flags.
4. Produces a **clean, muxable MP4**: strips the CENC boxes (`sinf`/`senc`/`saiz`/`saio`/`pssh`), restores sample-entry types (`encv`→`avc1`, `enca`→`mp4a`), recomputes box sizes, and fixes `trun.data_offset`. The output opens directly in ffmpeg and standard players.

## Supported

| Scheme | Status |
|--------|--------|
| `cenc` (AES-CTR, full-sample & subsample) | ✅ |
| `cbcs` (pattern, AES-CBC) | planned |
| `cens` (partial, AES-CTR) | planned |

| Feature | Status |
|---------|--------|
| Single content key per file | ✅ |
| Multi-key (per-track KID matching) | planned |

## Limitations

- Single content key per file (the common case). Multi-key support is planned.
- `cenc` scheme only for now; `cbcs`/`cens` are on the roadmap.
- `decrypt_bytes` loads the whole file into memory; use `decrypt_stream` (or
  `decrypt_file`, which streams internally) for pipes and large files.

## License

MIT — see [LICENSE](LICENSE).
