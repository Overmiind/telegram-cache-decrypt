#!/usr/bin/env python3
"""Verify a reconstructed MP4 by walking every AVC sample.

Each sample is a chain of [length][NAL] records that must exactly fill the
size the sample table declares. One misplaced byte desynchronises the chain,
so this catches reassembly errors that a container-level parse sails past.

Usage: verify.py <directory-of-mp4s>
"""
import struct, sys

def boxes(d,s=0,e=None):
    e=len(d) if e is None else e; p=s
    while p+8<=e:
        sz=struct.unpack('>I',d[p:p+4])[0]; t=d[p+4:p+8]; h=8
        if sz==1: sz=struct.unpack('>Q',d[p+8:p+16])[0]; h=16
        if sz<8 or p+sz>e: return
        yield p,t,sz,h; p+=sz

def traks(d):
    for p,t,sz,h in boxes(d):
        if t==b'moov':
            for q,t2,sz2,h2 in boxes(d,p+h,p+sz):
                if t2==b'trak': yield q+h2, q+sz2

def dig(d,s,e,typ):
    for p,t,sz,h in boxes(d,s,e):
        if t==typ: return p+h,p+sz
        if t in (b'mdia',b'minf',b'stbl',b'stsd',b'avc1',b'mp4a'):
            r=dig(d,p+h,p+sz,typ)
            if r: return r
    return None

def tables(d,ts,te):
    stsz=dig(d,ts,te,b'stsz'); stsc=dig(d,ts,te,b'stsc')
    stco=dig(d,ts,te,b'stco'); co64=dig(d,ts,te,b'co64')
    s,_=stsz; unif=struct.unpack('>I',d[s+4:s+8])[0]; n=struct.unpack('>I',d[s+8:s+12])[0]
    sizes=[unif]*n if unif else list(struct.unpack('>%dI'%n,d[s+12:s+12+4*n]))
    s,_=stsc; n=struct.unpack('>I',d[s+4:s+8])[0]
    sc=[struct.unpack('>III',d[s+8+12*i:s+20+12*i]) for i in range(n)]
    if stco: s,_=stco; n=struct.unpack('>I',d[s+4:s+8])[0]; offs=list(struct.unpack('>%dI'%n,d[s+8:s+8+4*n]))
    else:    s,_=co64; n=struct.unpack('>I',d[s+4:s+8])[0]; offs=list(struct.unpack('>%dQ'%n,d[s+8:s+8+8*n]))
    return sizes, sc, offs

def samples_per_chunk(sc, nchunks):
    out=[]
    for i,(first,spc,_) in enumerate(sc):
        last = sc[i+1][0]-1 if i+1<len(sc) else nchunks
        for _ in range(first,last+1): out.append(spc)
    return out[:nchunks]

def check(path, label):
    d=open(path,'rb').read()
    print('\n===',label,len(d),'bytes ===')
    for ti,(ts,te) in enumerate(traks(d)):
        i = d.find(b'avcC', ts, te)                # video track only
        if i < 0: continue
        lensz = (d[i + 8] & 3) + 1                  # lengthSizeMinusOne
        sizes,sc,offs = tables(d,ts,te)
        spc = samples_per_chunk(sc,len(offs))
        si=0; bad=None
        for ci,off in enumerate(offs):
            pos=off
            for _ in range(spc[ci]):
                if si>=len(sizes): break
                ssz=sizes[si]; q=pos; okS=True
                while q < pos+ssz:
                    if q+lensz>len(d): okS=False; break
                    L=int.from_bytes(d[q:q+lensz],'big')
                    if L<=0 or q+lensz+L>pos+ssz: okS=False; break
                    q+=lensz+L
                if not okS or q!=pos+ssz:
                    bad=(ci,si,off,pos); break
                pos+=ssz; si+=1
            if bad: break
        if bad:
            ci,si,off,pos=bad
            print('  video track: FIRST BAD sample #%d in chunk #%d (chunk offset %d, sample offset %d)'%(si,ci,off,pos))
            print('    chunks total %d, samples total %d'%(len(offs),len(sizes)))
            good=offs[ci-1] if ci else 0
            print('    last good chunk started at %d ; break lies between %d and %d'%(good,good,off))
        else:
            print('  video track: ALL %d samples parse cleanly (NAL lengths exact)'%len(sizes))

import os
_d = sys.argv[1] if len(sys.argv) > 1 else 'videos'
for fn in sorted(os.listdir(_d)):
    check(os.path.join(_d, fn), fn)
