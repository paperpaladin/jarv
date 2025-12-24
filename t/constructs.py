#!/usr/bin/env python3
"""Count the constructs the corpus actually contains.

A zip64 test on a corpus with no zip64 archive passes vacuously, and so does
a data descriptor test on a corpus where nothing streams. The counting is
done here rather than from jarv's output, with python3's zipfile and a raw
byte scan, so that a jarv that cannot see a construct reports zero of it and
the suite goes red rather than quietly agreeing with itself.

Exits non-zero if any construct listed as required is absent.
"""
import struct
import sys
import zipfile

REQUIRED = [
    "archives", "entries", "zip64_eocd", "zip64_extra", "data_descriptor",
    "no_data_descriptor", "stored", "deflated", "empty_entry", "directory",
    "archive_comment", "utf8_flag", "non_ascii_name", "name_over_72",
    "name_exactly_72", "signature_block", "signature_file", "manifest",
]


def main():
    counts = dict((k, 0) for k in REQUIRED)
    for path in sys.argv[1:]:
        counts["archives"] += 1
        raw = open(path, "rb").read()
        if raw.find(b"PK\x06\x06") >= 0:
            counts["zip64_eocd"] += 1
        # The archive comment length is the last two bytes of the 32-bit
        # end record, which is 22 bytes from the end when the comment is
        # empty. Read it from wherever the record actually is.
        i = raw.rfind(b"PK\x05\x06")
        if i >= 0:
            clen = struct.unpack("<H", raw[i + 20:i + 22])[0]
            if clen:
                counts["archive_comment"] += 1
        with zipfile.ZipFile(path) as z:
            for info in z.infolist():
                counts["entries"] += 1
                nb = info.orig_filename.encode("utf-8")
                if info.flag_bits & 0x08:
                    counts["data_descriptor"] += 1
                else:
                    counts["no_data_descriptor"] += 1
                if info.flag_bits & 0x800:
                    counts["utf8_flag"] += 1
                if info.compress_type == 0:
                    counts["stored"] += 1
                elif info.compress_type == 8:
                    counts["deflated"] += 1
                if info.file_size == 0 and not nb.endswith(b"/"):
                    counts["empty_entry"] += 1
                if nb.endswith(b"/"):
                    counts["directory"] += 1
                if any(b > 127 for b in nb):
                    counts["non_ascii_name"] += 1
                # "Name: " is six bytes; the manifest folds a line longer
                # than 72 bytes.
                if len(nb) + 6 > 72:
                    counts["name_over_72"] += 1
                if len(nb) + 6 == 72:
                    counts["name_exactly_72"] += 1
                if 0x0001 in dict(extra_ids(info.extra)):
                    counts["zip64_extra"] += 1
                if nb == b"META-INF/MANIFEST.MF":
                    counts["manifest"] += 1
                if nb.startswith(b"META-INF/") and nb.endswith(b".SF"):
                    counts["signature_file"] += 1
                if nb.startswith(b"META-INF/") and (
                        nb.endswith(b".RSA") or nb.endswith(b".DSA")
                        or nb.endswith(b".EC")):
                    counts["signature_block"] += 1
    missing = [k for k in REQUIRED if counts[k] == 0]
    for k in REQUIRED:
        print("construct %-20s %d" % (k, counts[k]))
    if missing:
        print("MISSING " + " ".join(missing))
        return 1
    return 0


def extra_ids(extra):
    out = []
    p = 0
    while p + 4 <= len(extra):
        hid, hlen = struct.unpack("<HH", extra[p:p + 4])
        out.append((hid, extra[p + 4:p + 4 + hlen]))
        p += 4 + hlen
    return out


sys.exit(main())
