#!/usr/bin/env python3
"""A zip writer with the switches the jar tool does not have.

jarsigner rewrites the archive it signs, so the only way to get a signed
zip64 archive, or a signed archive whose entries are stored rather than
deflated, is to sign first and rebuild the container afterwards. That is
sound: a JAR signature covers entry contents and manifest bytes, nothing
about the container, so rebuilding it must leave the signature valid. If it
does not, jarsigner will say so and that is a finding rather than a bug in
this script.

Reading is done with python3's zipfile, which is a third independent zip
reader after the JDK's and Info-ZIP's. Writing is by hand because zipfile
will not emit a zip64 end record for a small archive however it is asked.

  mkzip.py rebuild IN OUT [--zip64] [--dd|--no-dd] [--store] [--comment TEXT]
  mkzip.py add     IN OUT NAME         (content on stdin)
  mkzip.py replace IN OUT NAME         (content on stdin)
  mkzip.py drop    IN OUT NAME
  mkzip.py bitflip IN OUT NAME OFFSET  (one byte of an entry's stored data)
"""
import binascii
import struct
import sys
import zipfile

LOC = 0x04034B50
CEN = 0x02014B50
EOCD = 0x06054B50
DD = 0x08074B50
Z64EOCD = 0x06064B50
Z64LOC = 0x07064B50
M32 = 0xFFFFFFFF


def read(path):
    """[(name_bytes, data, method_hint)] in central directory order."""
    out = []
    with zipfile.ZipFile(path) as z:
        for i in z.infolist():
            nb = i.orig_filename.encode("utf-8")
            out.append([nb, z.read(i.filename), i.compress_type])
    return out


def deflate(data):
    import zlib
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def write(path, items, zip64=False, dd=True, store=False, comment=b""):
    out = bytearray()
    central = bytearray()
    count = 0
    for nb, data, hint in items:
        isdir = nb.endswith(b"/")
        method = 0 if (store or isdir or not data) else 8
        body = data if method == 0 else deflate(data)
        crc = binascii.crc32(data) & M32
        flags = 0x0800  # names are UTF-8
        # A stored entry may not carry a data descriptor: the JDK refuses
        # the combination with "only DEFLATED entries can have EXT
        # descriptor", measured, not guessed.
        if dd and not isdir and method == 8:
            flags |= 0x0008
        loff = len(out)
        ex = b""
        streamed = bool(flags & 0x0008)
        lcrc = 0 if streamed else crc
        if zip64:
            # The local copy of the zip64 field holds BOTH sizes always,
            # and both are zero when a data descriptor will carry them.
            # Writing the real sizes here while the 32-bit slots say zero
            # is what the JDK rejects with "invalid entry size (expected 0
            # but got N bytes)", which is how this was found.
            lcs = lus = 0 if streamed else M32
            ex = struct.pack("<HHQQ", 1, 16,
                             0 if streamed else len(data),
                             0 if streamed else len(body))
        else:
            lcs = 0 if streamed else len(body)
            lus = 0 if streamed else len(data)
        out += struct.pack("<IHHHHHIIIHH", LOC, 45 if zip64 else 20, flags,
                           method, 0, 0x21, lcrc, lcs, lus, len(nb), len(ex))
        out += nb + ex + body
        if flags & 0x0008:
            if zip64:
                out += struct.pack("<IIQQ", DD, crc, len(body), len(data))
            else:
                out += struct.pack("<IIII", DD, crc, len(body), len(data))
        cex = b""
        ccs, cus, cloff = len(body), len(data), loff
        if zip64:
            # The central copy is sparse: only the overflowed values, in the
            # order uncompressed, compressed, offset.
            cex = struct.pack("<HHQQQ", 1, 24, len(data), len(body), loff)
            ccs = cus = cloff = M32
        central += struct.pack("<IHHHHHHIIIHHHHHII", CEN, 45 if zip64 else 20,
                               45 if zip64 else 20, flags, method, 0, 0x21,
                               crc, ccs, cus, len(nb), len(cex), 0, 0, 0, 0,
                               cloff)
        central += nb + cex
        count += 1
    cdoff = len(out)
    out += central
    cdsize = len(central)
    if zip64:
        z64off = len(out)
        out += struct.pack("<IQHHIIQQQQ", Z64EOCD, 44, 45, 45, 0, 0,
                           count, count, cdsize, cdoff)
        out += struct.pack("<IIQI", Z64LOC, 0, z64off, 1)
        out += struct.pack("<IHHHHIIH", EOCD, 0, 0, 0xFFFF, 0xFFFF,
                           M32, M32, len(comment))
    else:
        out += struct.pack("<IHHHHIIH", EOCD, 0, 0, count, count,
                           cdsize, cdoff, len(comment))
    out += comment
    with open(path, "wb") as f:
        f.write(bytes(out))


def main():
    cmd = sys.argv[1]
    src, dst = sys.argv[2], sys.argv[3]
    items = read(src)
    if cmd == "rebuild":
        opts = sys.argv[4:]
        comment = b""
        if "--comment" in opts:
            comment = opts[opts.index("--comment") + 1].encode()
        write(dst, items, zip64="--zip64" in opts, dd="--no-dd" not in opts,
              store="--store" in opts, comment=comment)
    elif cmd == "add":
        name = sys.argv[4].encode("utf-8")
        items.append([name, sys.stdin.buffer.read(), 8])
        write(dst, items)
    elif cmd == "replace":
        name = sys.argv[4].encode("utf-8")
        data = sys.stdin.buffer.read()
        hit = 0
        for it in items:
            if it[0] == name:
                it[1] = data
                hit += 1
        if hit != 1:
            sys.exit("replace: %s matched %d entries" % (sys.argv[4], hit))
        write(dst, items)
    elif cmd == "drop":
        name = sys.argv[4].encode("utf-8")
        keep = [i for i in items if i[0] != name]
        if len(keep) == len(items):
            sys.exit("drop: no entry named %s" % sys.argv[4])
        write(dst, keep)
    elif cmd == "bitflip":
        name = sys.argv[4].encode("utf-8")
        off = int(sys.argv[5])
        for it in items:
            if it[0] == name:
                b = bytearray(it[1])
                b[off] ^= 0x01
                it[1] = bytes(b)
        write(dst, items)
    else:
        sys.exit(__doc__)


main()
