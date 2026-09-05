#!/usr/bin/env python3
"""Reconstruct whole videos from Telegram Desktop's big-file media cache.

Usage: tgvideos.py [outdir] [-k key_datas] [-c cache_dir] [-t tdata]

Cache layout for a streamed video:
  * The FIRST entry is a part map, not a contiguous prefix. It is a series of
    groups: [uint32 partCount] then, per part, [uint32 fileOffset]
    [uint32 partSize] followed by partSize bytes belonging at fileOffset.
    Parts are 128 KiB. Leaving those 8-byte part headers inline is what
    shifts the stream and makes playback die after half a second.
  * Further 8 MiB slices live as separate, descriptor-less entries in other
    media_cache/0/XX/ subfolders, written in download order.

The key file and the cache directory are addressed independently, so they
need not sit in the same profile.
"""
import argparse
import os
import struct
import sys

from tdecrypt import (add_common_args, read_key, repair_mp4, resolve,
                      storage_file_read)
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
    """Where the MP4 ends per its own boxes; stops at trailing block padding.

    Give this the whole assembled head, not just its first part: moov is
    routinely larger than one 128 KiB part, and stopping early means never
    reaching mdat and mistaking the end of moov for the end of the file.
    (A genuinely sparse head could still cut the walk short at a zero hole;
    heads seen in practice are contiguous from offset 0.)"""
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
    ap = add_common_args(argparse.ArgumentParser(
        description='Rebuild whole videos from a Telegram Desktop media cache.'))
    args = ap.parse_args()
    keyfile, cachedir = resolve(args)
    outdir = args.out
    os.makedirs(outdir, exist_ok=True)
    key = read_key(keyfile)

    entries = []
    for root, _, files in os.walk(cachedir):
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
        head = bytearray(covered)
        for off, body in pieces:
            head[off:off + len(body)] = body
        end = declared_end(bytes(head))
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

        buf = bytearray(covered)
        for off, body in pieces:
            buf[off:off + len(body)] = body
        done = covered >= end and end > 0
        data = bytes(buf[:end]) if done else bytes(buf)
        fixed = None
        if not done:
            data, fixed = repair_mp4(data)   # shrink mdat to what is present
        dur = duration(data)

        print('video%d  <- %s%s' % (i, name, ''.join(' + ' + n for n in parts)))
        print('   %d pieces covering file[0 .. %d]' % (len(pieces), covered))
        print('   %s  %d bytes (%.1f MB)  %s' % (
            'COMPLETE' if done else 'INCOMPLETE (%.1f%% of %d)' % (
                100.0 * covered / end, end) if end else 'NO DECLARED SIZE',
            len(data), len(data) / 1048576,
            '%.1fs (%d:%02d)' % (dur, int(dur) // 60, int(dur) % 60) if dur else '?'))
        if fixed:
            print('   mdat shrunk %d -> %d so the fragment plays' % fixed)
        tag = ('%ds' % int(dur)) if dur else 'nodur'
        if not done:
            tag += '_incomplete%dpct' % (100.0 * covered / end) if end else '_partial'
        out = os.path.join(outdir, 'video%d_%s_%s.mp4' % (i, name, tag))
        with open(out, 'wb') as f:
            f.write(data)
        print('   ->', out, '\n')


if __name__ == '__main__':
    main()
