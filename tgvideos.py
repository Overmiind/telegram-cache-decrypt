#!/usr/bin/env python3
"""Reconstruct whole videos from Telegram Desktop's big-file media cache.

Usage: tgvideos.py <outdir> [tdata_with_cache] [tdata_with_key_datas]

Cache layout for a streamed video:
  * The FIRST entry is a part map, not a contiguous prefix. It is a series of
    groups: [uint32 partCount] then, per part, [uint32 fileOffset]
    [uint32 partSize] followed by partSize bytes belonging at fileOffset.
    Parts are 128 KiB. Leaving those 8-byte part headers inline is what
    shifts the stream and makes playback die after half a second.
  * Further 8 MiB slices live as separate, descriptor-less entries in other
    media_cache/0/XX/ subfolders, written in download order.

A sandboxed (Sandboxie) Telegram keeps its own cache but inherits key_datas
from the real profile by copy-on-write, hence the separate key path.
"""
import os
import struct
import sys

from tdecrypt import read_key, storage_file_read

TDATA = os.path.join(os.environ.get('APPDATA', ''), 'Telegram Desktop', 'tdata')
PART = 131072                       # 128 KiB
SLICE = 64 * PART                   # 8 MiB


def segments(raw):
    """[(fileOffset, data)] if raw is part-mapped, else None (raw slice)."""
    p, out = 0, []
    while p + 4 <= len(raw):
        cnt = struct.unpack('<I', raw[p:p + 4])[0]
        if not (0 < cnt <= 64):
            break
        q, grp = p + 4, []
        for _ in range(cnt):
            if q + 8 > len(raw):
                break
            off, ps = struct.unpack('<II', raw[q:q + 8])
            if ps == 0 or ps > PART or off % PART:
                grp = None
                break
            grp.append((off, raw[q + 8:q + 8 + ps]))
            q += 8 + ps
        if not grp:
            break
        out += grp
        p = q
    return out or None


def is_box(t):
    return len(t) == 4 and all(0x20 <= c <= 0x7e for c in t)


def declared_end(d):
    """Where the MP4 ends per its own boxes; stops at trailing block padding."""
    end = p = 0
    while p + 8 <= len(d):
        sz = struct.unpack('>I', d[p:p + 4])[0]
        t = d[p + 4:p + 8]
        if sz == 1:
            sz = struct.unpack('>Q', d[p + 8:p + 16])[0]
        if sz < 8 or not is_box(t):
            break
        end = p + sz
        p = end
    return end


def duration(d):
    """Seconds from mvhd, located inside moov (which may sit at either end)."""
    p = 0
    while p + 8 <= len(d):
        sz = struct.unpack('>I', d[p:p + 4])[0]
        t = d[p + 4:p + 8]
        if sz == 1:
            sz = struct.unpack('>Q', d[p + 8:p + 16])[0]
        if sz < 8 or not is_box(t):
            return None
        if t == b'moov':
            i = d.find(b'mvhd', p, p + sz)
            if i < 0:
                return None
            ts, du = struct.unpack('>II', d[i + 16:i + 24])
            return du / ts if ts else None
        p += sz
    return None


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else 'videos'
    tdata = sys.argv[2] if len(sys.argv) > 2 else TDATA      # cache to scan
    keydir = sys.argv[3] if len(sys.argv) > 3 else tdata     # key_datas home
    os.makedirs(outdir, exist_ok=True)
    key = read_key(os.path.join(keydir, 'key_datas'))

    entries = []
    for root, _, files in os.walk(os.path.join(tdata, 'user_data', 'media_cache')):
        for n in files:
            if n in ('version', 'binlog'):
                continue
            p = os.path.join(root, n)
            raw = storage_file_read(p, key)
            entries.append([os.path.getmtime(p), n, raw, segments(raw)])
    entries.sort(key=lambda e: e[0])

    heads = [e for e in entries if e[3] or e[2][4:8] == b'ftyp']
    loose = [e for e in entries if e not in heads and len(e[2]) >= 65536]
    print('%d entries: %d video heads, %d loose slices\n'
          % (len(entries), len(heads), len(loose)))

    used = set()
    for i, (mt, name, raw, segs) in enumerate(heads, 1):
        pieces = list(segs) if segs else [(0, raw)]
        covered = max(o + len(b) for o, b in pieces)
        end = declared_end(pieces[0][1])
        nxt = heads[i][0] if i < len(heads) else float('inf')

        parts = []
        pool = [e for e in loose if mt <= e[0] < nxt]
        while covered < end:
            need = end - covered
            pick = None
            for e in pool:                       # full slices in download order
                if e[1] in used:
                    continue
                if need >= SLICE and len(e[2]) == SLICE:
                    pick = e
                    break
                if need < SLICE and abs(len(e[2]) - need) <= 16:
                    pick = e                     # final short slice
                    break
            if pick is None:
                break
            pieces.append((covered, pick[2]))
            parts.append(pick[1])
            used.add(pick[1])
            covered += len(pick[2])

        buf = bytearray(max(end, covered))
        for off, body in pieces:
            buf[off:off + len(body)] = body
        data = bytes(buf[:end]) if end else bytes(buf)
        dur = duration(data)
        done = covered >= end and end > 0

        print('video%d  <- %s%s' % (i, name, ''.join(' + ' + n for n in parts)))
        print('   %d pieces covering file[0 .. %d]' % (len(pieces), covered))
        print('   %s  %d bytes (%.1f MB)  %s' % (
            'COMPLETE' if done else 'INCOMPLETE (%.1f%%)' % (100.0 * covered / end),
            len(data), len(data) / 1048576,
            '%.1fs (%d:%02d)' % (dur, int(dur) // 60, int(dur) % 60) if dur else '?'))
        out = os.path.join(outdir, 'video%d_%s_%s.mp4'
                           % (i, name, ('%ds' % int(dur)) if dur else 'partial'))
        with open(out, 'wb') as f:
            f.write(data)
        print('   ->', out, '\n')


if __name__ == '__main__':
    main()
