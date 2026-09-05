# telegram-cache-decrypt

Decrypt Telegram Desktop's local media cache and rebuild whole videos out of it.

Telegram Desktop stores cached media encrypted under your profile's local key.
This reads `tdata`, decrypts the cache, and reassembles streamed videos —
including large ones, which are **split across several cache entries in
different folders** and are not recoverable by simply decrypting files
one at a time.

Pure Python plus `pycryptodome`. No PyQt5, no `cffi`, no `tgcrypto`, no
OpenSSL shared objects. Works on Windows, where most existing scripts don't.

Only works on your own profile: it needs the `key_datas` from your own `tdata`.

---

## Install

```
pip install -r requirements.txt
```

## Usage

Rebuild every video in the cache:

```
python tgvideos.py out_dir
```

Decrypt every cache entry as-is, without reassembly:

```
python tdecrypt.py out_dir
```

Both take the same options. The key file and the cache directory are addressed
independently and neither implies the other, so they need not come from the
same profile — or from a live install at all.

```
-k, --key FILE    key_datas file        (default: <tdata>/key_datas)
-c, --cache DIR   directory to walk     (default: <tdata>/user_data/media_cache)
-t, --tdata DIR   profile directory, used only to derive those two defaults
```

`--tdata` itself defaults to `%APPDATA%\Telegram Desktop\tdata`, so with a
normal install you can pass nothing. Otherwise point `--cache` at any directory
of encrypted entries and `--key` at any matching `key_datas`:

```
python tgvideos.py out_dir -c /path/to/some/media_cache -k /path/to/key_datas
```

Check the results:

```
python verify.py out_dir
```

---

## How it works

### 1. The local key

`tdata/key_datas` is a `TDF$` container: 4-byte magic, 4-byte version, a
Qt-serialised body, and a trailing MD5 of `body || size || version || magic`.
Each field is a big-endian `uint32` length followed by that many bytes — no Qt
needed to read it.

The body holds a 32-byte salt and an encrypted blob. The passcode key is

```
PBKDF2-HMAC-SHA512( SHA512(salt || passcode || salt), salt, iter, 256 )
```

with `iter = 1` for an empty passcode and `100000` otherwise. That key decrypts
the blob with **AES-256-IGE** (the MTProto variant: a 16-byte `msgKey` prefix,
then key and IV derived through four SHA-1 rounds), yielding the 256-byte local
key. The first 16 bytes of the plaintext's SHA-1 must equal the `msgKey`, which
makes the whole step self-verifying.

`settingss` uses an **older derivation** — `PBKDF2-HMAC-SHA1` with 4 iterations
for an empty passcode — so the same routine will not open it. Worth knowing if
you want to read the configured download path.

### 2. Cache files

Each cache entry is a `TDEF` file: magic, a 64-byte salt, then AES-256-CTR data.

```
key = SHA256( localkey[:128] || salt[:32] )
iv  = SHA256( localkey[128:] || salt[32:] )[:16]
```

The counter is a full 128-bit big-endian block. The first 48 decrypted bytes are
a header whose checksum, `SHA256(localkey || salt || data[:16])`, confirms the
key before anything else is read.

Payloads are padded up to a 16-byte boundary, so the decrypted length is not the
true length — expect a few bytes of tail junk.

### 3. The part map — the bit that matters

A small cached file is just its bytes. **A streamed video is not.**

The first entry of a video is a *sparse map*, not a contiguous prefix:

```
[uint32 partCount]
    [uint32 fileOffset][uint32 partSize]  <partSize bytes>
    [uint32 fileOffset][uint32 partSize]  <partSize bytes>
    ...
```

Parts are 128 KiB. Those 8-byte per-part headers sit *between* the data blocks.
Treat the entry as one contiguous run and every part after the first is shifted
by 8 more bytes — the file still parses as valid MP4 and still reports the right
duration, but playback dies after about half a second.

The entry covers the first 8 MiB. Beyond that, the video continues as further
8 MiB slices stored as **separate, header-less entries in other
`media_cache/0/XX/` subfolders**. They are raw data with no magic bytes, so they
look like noise and are easy to mistake for unrelated files.

So one video can be spread over a dozen entries in a dozen folders, of which
exactly one looks like a video. That is why a video you just watched appears to
be missing from the cache.

Reassembly: parse the head into parts, place each at its declared offset, then
append the loose 8 MiB slices in write order, plus a final short slice sized to
land exactly on the total the MP4 boxes declare.

That total has to come from walking the boxes of the **whole assembled head**,
not just its first part. `moov` is routinely larger than one 128 KiB part — a
2:43 clip here carries a 162 KB one — and a walk that stops at the end of the
first part never reaches `mdat`, so it mistakes the end of `moov` for the end of
the file and truncates a 130 MB video to 163 KB.

### 4. Verifying it

Container-level checks are not enough here — the misaligned build above parses
cleanly, walks its box tree, and reports the correct duration while being
unplayable.

`verify.py` uses the sample table instead. Every AVC sample is a chain of
`[length][NAL]` records that must exactly fill the size `stsz` declares for it.
A single misplaced byte desynchronises the chain and the walk fails at that
sample. It also pinpoints *where* a build went wrong, which is how the 128 KiB
part boundary was found in the first place.

A clean run reports every sample in every track:

```
=== video3.mp4 92579061 bytes ===
  video track: ALL 6676 samples parse cleanly (NAL lengths exact)
```

---

## Notes

**Slice order.** Full slices are all exactly 8 MiB, so nothing in their contents
says which comes first; they are ordered by file write time. That is download
order, which equals file order for a straight-through watch. Seeking around
mid-download could break the assumption — `verify.py` will catch it if so.

**Split key and cache.** A cache directory and the `key_datas` that opens it do
not have to live together. Copied profiles, backups, disk images and
containerised or path-redirected installs can all separate them — a redirected
install often keeps its cache in the redirected location while still reading
the original profile's key. `--key` and `--cache` are independent for exactly
this reason; the only requirement is that the cache was written under the key
you supply.

**Partial downloads.** Telegram only caches what you actually watched. When the
slices don't add up to the declared size, the rebuild is reported as
`INCOMPLETE` with the percentage present, the output is truncated to what is
actually there, and its `mdat` header is shrunk to match — so the fragment plays
instead of trailing off into megabytes of zeros.

**Fragmented MP4.** Some cached streams are fMP4/DASH — `sidx` plus a chain of
`moof`/`mdat` fragments, often HEVC — rather than progressive MP4. They rebuild
and play normally, but they report a duration of `?`, because `mvhd` carries
zero, and `verify.py` reports nothing for them: it reads the `stsz`/`stco`
sample tables, which fragmented files don't have. Their samples are described by
`trun` inside each `moof` instead.

**Joining clips.** Cached videos often differ in resolution, so a stream-copy
concat won't work; scale to a common size and re-encode, e.g.

```
scale=W:H:force_original_aspect_ratio=decrease,pad=W:H:(ow-iw)/2:(oh-ih)/2,setsar=1
```

## Layout

| file | purpose |
| --- | --- |
| `tdecrypt.py` | local key, `TDEF` decryption, type sniffing |
| `tgvideos.py` | part-map parsing and multi-slice video reassembly |
| `verify.py` | per-sample NAL integrity check |
