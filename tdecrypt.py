#!/usr/bin/env python3
"""Windows port of the tdata decryptor.

Drops PyQt5 / cffi / tgcrypto / ffi_openssl.so in favour of stdlib + pycryptodome.
Key derivation, IGE and CTR semantics are kept byte-for-byte compatible.
"""
import argparse
import hashlib
import os
import struct
import sys

from Crypto.Cipher import AES
from Crypto.Util import Counter


# ---------------------------------------------------------------- primitives

def sha1(data):
    return hashlib.sha1(data).digest()


def sha256(data):
    return hashlib.sha256(data).digest()


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def ige256_decrypt(src, key, iv, swap_iv=False):
    """AES-256-IGE decrypt. m_i = D(c_i ^ m_{i-1}) ^ c_{i-1}."""
    if len(src) % 16:
        raise ValueError('IGE input not block aligned')
    ecb = AES.new(key, AES.MODE_ECB)
    prev_c, prev_m = (iv[16:32], iv[:16]) if swap_iv else (iv[:16], iv[16:32])
    out = bytearray()
    for i in range(0, len(src), 16):
        c = src[i:i + 16]
        m = xor(ecb.decrypt(xor(c, prev_m)), prev_c)
        out += m
        prev_c, prev_m = c, m
    return bytes(out)


def prepareAES_oldmtp(key, msgKey):
    sha1_a = sha1(msgKey[:16] + key[8:8 + 32])
    sha1_b = sha1(key[8 + 32: 8 + 32 + 16] + msgKey[:16] + key[8 + 48: 8 + 48 + 16])
    sha1_c = sha1(key[8 + 64: 8 + 64 + 32] + msgKey[:16])
    sha1_d = sha1(msgKey[:16] + key[8 + 96: 8 + 96 + 32])

    aesKey = sha1_a[:8] + sha1_b[8: 8 + 12] + sha1_c[4: 4 + 12]
    aesIv = sha1_a[8: 8 + 12] + sha1_b[:8] + sha1_c[16: 16 + 4] + sha1_d[:8]
    return aesKey, aesIv


def decryptLocal(encrypted, key, swap_iv=False):
    encryptedKey = encrypted[:16]
    aesKey, aesIv = prepareAES_oldmtp(key, encryptedKey)
    decrypted = ige256_decrypt(encrypted[16:], aesKey, aesIv, swap_iv)
    if sha1(decrypted)[:16] != encryptedKey:
        raise ValueError('bad checksum for decrypted data')
    dataLen = int.from_bytes(decrypted[:4], 'little')
    return decrypted[4:dataLen]


def createLocalKey(passcode, salt):
    hashKey = hashlib.sha512(salt)
    hashKey.update(passcode)
    hashKey.update(salt)
    iterCount = 100000 if passcode else 1
    return hashlib.pbkdf2_hmac('sha512', hashKey.digest(), salt, iterCount, 256)


# ------------------------------------------------------------- TDF$ handling

class Stream:
    """Minimal stand-in for QDataStream: readBytes() is a BE uint32 length."""

    def __init__(self, data):
        self.data = data
        self.pos = 0

    def readBytes(self):
        n = int.from_bytes(self.data[self.pos:self.pos + 4], 'big')
        self.pos += 4
        if n == 0xFFFFFFFF:
            return b''
        out = self.data[self.pos:self.pos + n]
        self.pos += n
        return out


def readFile(name):
    with open(name, 'rb') as f:
        if f.read(4) != b'TDF$':
            raise ValueError('wrong file type')
        version = f.read(4)
        data = f.read()

    m = hashlib.md5()
    m.update(data[:-16])
    m.update((len(data) - 16).to_bytes(4, 'little'))
    m.update(version)
    m.update(b'TDF$')
    if m.digest() != data[-16:]:
        raise ValueError('checksum mismatch')
    return Stream(data)


def read_key(name, passcode=b''):
    qstream = readFile(name)
    salt = qstream.readBytes()
    key_encrypted = qstream.readBytes()
    PassKey = createLocalKey(passcode, salt)
    for swap in (False, True):
        try:
            key = decryptLocal(key_encrypted, PassKey, swap)
            if swap:
                print('  (note: IGE IV halves swapped)')
            return key
        except ValueError:
            if swap:
                raise
    raise ValueError('unreachable')


# ------------------------------------------------------------- TDEF handling

def storage_file_read(path, key):
    with open(path, 'rb') as f:
        if f.read(4) != b'TDEF':
            raise ValueError('wrong file type')
        salt = f.read(64)

        real_key = sha256(key[:len(key) // 2] + salt[:32])
        iv = sha256(key[len(key) // 2:] + salt[32:])[:16]

        # Full 128-bit big-endian counter, matching OpenSSL ctr128_inc.
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, 'big'),
                          little_endian=False)
        d = AES.new(real_key, AES.MODE_CTR, counter=ctr)

        data = d.decrypt(f.read(16 + 32))   # block aligned: keystream carries on
        if sha256(key + salt + data[:16]) != data[16:]:
            raise ValueError('wrong key')
        return d.decrypt(f.read())


# -------------------------------------------------------------------- driver

MAGICS = [
    (b'\xff\xd8\xff', 'jpg'), (b'\x89PNG\r\n\x1a\n', 'png'),
    (b'GIF8', 'gif'), (b'RIFF', 'webp_or_avi'), (b'\x1a\x45\xdf\xa3', 'webm'),
    (b'OggS', 'ogg'), (b'%PDF', 'pdf'), (b'PK\x03\x04', 'zip'),
    (b'ID3', 'mp3'), (b'\x00\x01\x00\x00', 'ttf'), (b'\x1f\x8b', 'gz'),
]


def strip_bigfile_prefix(data):
    """Big-file cache entries carry a 12-byte Telegram header before the media."""
    if len(data) > 20 and data[16:20] == b'ftyp':
        return data[12:]
    return data


def repair_mp4(data):
    """Streamed videos are cached partially: mdat declares the full length but
    only the watched prefix is present. Shrink mdat so players accept it."""
    if len(data) < 16 or data[4:8] != b'ftyp':
        return data, None
    p = 0
    while p + 16 <= len(data):
        sz = struct.unpack('>I', data[p:p + 4])[0]
        wide = (sz == 1)
        if wide:
            sz = struct.unpack('>Q', data[p + 8:p + 16])[0]
        if data[p + 4:p + 8] == b'mdat' and p + sz > len(data):
            have = len(data) - p
            out = bytearray(data)
            if wide:
                struct.pack_into('>Q', out, p + 8, have)
            else:
                struct.pack_into('>I', out, p, have)
            return bytes(out), (sz, have)
        if sz < 8 or p + sz > len(data):
            break
        p += sz
    return data, None


def true_length(data, ext):
    """Cache files are padded to a 16-byte boundary; the real length lives in
    the binlog we don't have. For MP4 the container itself tells us."""
    if ext != 'mp4':
        return len(data)
    p = 0
    while p + 8 <= len(data):
        size = int.from_bytes(data[p:p + 4], 'big')
        if size == 1:
            size = int.from_bytes(data[p + 8:p + 16], 'big')
        if size < 8 or p + size > len(data):
            break
        p += size
    return p if p else len(data)


def sniff(data):
    if data[4:8] in (b'ftyp',):
        return 'mp4'
    for magic, ext in MAGICS:
        if data.startswith(magic):
            return ext
    return None


DEFAULT_TDATA = os.path.join(
    os.environ.get('APPDATA', ''), 'Telegram Desktop', 'tdata')


def add_common_args(ap):
    """Key and cache are addressed independently; neither implies the other."""
    ap.add_argument('out', nargs='?', default='out',
                    help='output directory (default: ./out)')
    ap.add_argument('-t', '--tdata', default=DEFAULT_TDATA,
                    help='profile directory, used only to derive the defaults '
                         'for --key and --cache')
    ap.add_argument('-k', '--key', metavar='FILE',
                    help='key_datas file (default: <tdata>/key_datas)')
    ap.add_argument('-c', '--cache', metavar='DIR',
                    help='directory of encrypted entries to walk '
                         '(default: <tdata>/user_data/media_cache)')
    return ap


def resolve(args):
    """-> (key_datas path, cache directory)."""
    return (args.key or os.path.join(args.tdata, 'key_datas'),
            args.cache or os.path.join(args.tdata, 'user_data', 'media_cache'))


def main():
    ap = add_common_args(argparse.ArgumentParser(
        description='Decrypt Telegram Desktop cache entries.'))
    args = ap.parse_args()
    keyfile, cachedir = resolve(args)

    print('key   :', keyfile)
    print('cache :', cachedir)
    LocalKey = read_key(keyfile)
    print('local key ok, %d bytes' % len(LocalKey))
    print()
    assert len(LocalKey) == 256, 'unexpected local key length'

    os.makedirs(args.out, exist_ok=True)
    for root, _, files in os.walk(cachedir):
        for name in files:
            if name in ('version', 'binlog'):
                continue
            path = os.path.join(root, name)
            print('Decrypting', path)
            data = storage_file_read(path, LocalKey)
            data = strip_bigfile_prefix(data)
            data, partial = repair_mp4(data)
            if partial:
                print('  PARTIAL download: %d of %d mdat bytes (%.1f%%)'
                      % (partial[1], partial[0], 100.0 * partial[1] / partial[0]))
            ext = sniff(data)
            padded = len(data)
            data = data[:true_length(data, ext)]
            print('  %d bytes (%d block padding trimmed), head=%s, type=%s'
                  % (len(data), padded - len(data), data[:16].hex(),
                     ext or 'unknown'))
            out = os.path.join(args.out, name + ('.' + ext if ext else '.bin'))
            with open(out, 'wb') as f:
                f.write(data)
            print('  ->', out)


if __name__ == '__main__':
    main()
