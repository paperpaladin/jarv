#!/usr/bin/env python3
"""Count the constructs the corpus actually contains.

A zip64 test on a corpus with no zip64 archive passes vacuously, and so does
a data descriptor test on a corpus where nothing streams. The counting is
done here rather than from jarv's output, with python3's zipfile and a raw
byte scan, so that a jarv that cannot see a construct reports zero of it and
the suite goes red rather than quietly agreeing with itself.

Exits non-zero if any construct listed as required is absent.
"""
import hashlib
import os
import re
import struct
import subprocess
import sys
import zipfile

REQUIRED = [
    "archives", "entries", "zip64_eocd", "zip64_extra", "data_descriptor",
    "no_data_descriptor", "stored", "deflated", "empty_entry", "directory",
    "archive_comment", "utf8_flag", "non_ascii_name", "name_over_72",
    "name_exactly_72", "signature_block", "signature_file", "manifest",
    "fold_continuation", "fold_space_after_marker", "fold_splits_utf8",
    "decoy_end_record", "rsa_block", "ec_block", "curve_p256", "curve_p384",
    "curve_p521", "multi_cert_block", "issuer_differs_from_subject",
    "two_signature_files", "covered_by_one_sf_only", "stale_manifest_digest",
    "dsa_block", "sha1_entry_digest",
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
        if raw.count(b"PK\x05\x06") > 1:
            counts["decoy_end_record"] += 1
        try:
            z = zipfile.ZipFile(path)
        except Exception:
            # python3's zipfile is fooled by the decoy end records and
            # refuses the archive. Counted and skipped rather than fatal:
            # the construct it cannot see is the one being counted.
            print("construct %-20s %s" % ("python_refused", path))
            continue
        with z:
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
                    if re.search(rb"(?im)^SHA-?1-Digest:", z.read(info)):
                        counts["sha1_entry_digest"] += 1
                    folds(counts, z.read(info))
                if nb.startswith(b"META-INF/") and nb.endswith(b".SF"):
                    counts["signature_file"] += 1
                if nb.startswith(b"META-INF/") and (
                        nb.endswith(b".RSA") or nb.endswith(b".DSA")
                        or nb.endswith(b".EC")):
                    counts["signature_block"] += 1
                    if nb.endswith(b".RSA"):
                        counts["rsa_block"] += 1
                    if nb.endswith(b".EC"):
                        counts["ec_block"] += 1
                    if nb.endswith(b".DSA"):
                        counts["dsa_block"] += 1
                    block(counts, z.read(info))
            coverage(counts, z)
    missing = [k for k in REQUIRED if counts[k] == 0]
    for k in REQUIRED:
        print("construct %-20s %d" % (k, counts[k]))
    if missing:
        print("MISSING " + " ".join(missing))
        return 1
    return 0


def coverage(counts, z):
    """Which .SF files name which entries, read as text.

    No ASN.1 and no jarv: a signature file is a manifest, and whether a
    given entry has a section in it is a question about lines. An entry
    named by one signature file and not by another is the partially
    covered case, and a corpus without one cannot test it.
    """
    names = [i.filename for i in z.infolist()]
    sfs = [n for n in names
           if n.upper().startswith("META-INF/") and n.upper().endswith(".SF")
           and "/" not in n[len("META-INF/"):]]
    if len(sfs) < 2:
        return
    counts["two_signature_files"] += 1
    sets = []
    for sf in sfs:
        sets.append(set(section_names(z.read(sf))))
    union = set().union(*sets)
    for name in union:
        if any(name not in s for s in sets):
            counts["covered_by_one_sf_only"] += 1
    # A signature file whose whole-manifest digest no longer matches the
    # manifest is the archive that forces the per-section fallback.
    try:
        mf = z.read("META-INF/MANIFEST.MF")
    except KeyError:
        return
    for sf in sfs:
        if not whole_manifest_matches(z.read(sf), mf):
            counts["stale_manifest_digest"] += 1


def section_names(raw):
    """Values of every Name attribute, with continuation lines joined."""
    out = []
    for line in unfold(raw):
        if line[:6].lower() == b"name: ":
            out.append(line[6:].decode("utf-8", "replace"))
    return out


def unfold(raw):
    lines = []
    for phys in re.split(rb"\r\n|\n|\r", raw):
        if phys[:1] == b" " and lines:
            lines[-1] += phys[1:]
        else:
            lines.append(phys)
    return lines


def whole_manifest_matches(sf, mf):
    for line in unfold(sf):
        low = line.lower()
        if b"-digest-manifest:" not in low or b"main-attributes" in low:
            continue
        alg, _, value = line.partition(b"-Digest-Manifest: ")
        if not value:
            continue
        try:
            import base64
            want = base64.b64decode(value, validate=True)
            got = hashlib.new(alg.decode().replace("-", "").lower(),
                              mf).digest()
        except Exception:
            continue
        if want == got:
            return True
    return False


def block(counts, der):
    """What is inside a signature block, asked of openssl, not of jarv.

    The curve and the certificate count need an ASN.1 decoder and python
    has none in its standard library, so openssl is the one asked. It is
    an oracle here as everywhere else in this suite.
    """
    import tempfile
    fd, path = tempfile.mkstemp(suffix=".der")
    os.write(fd, der)
    os.close(fd)
    try:
        p = subprocess.run(["openssl", "pkcs7", "-inform", "DER", "-in", path,
                            "-print_certs"], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL)
        text = p.stdout.decode("utf-8", "replace")
        if text.count("BEGIN CERTIFICATE") > 1:
            counts["multi_cert_block"] += 1
        subs = re.findall(r"^subject=(.*)$", text, re.M)
        isss = re.findall(r"^issuer=(.*)$", text, re.M)
        for a, b in zip(subs, isss):
            if a != b:
                counts["issuer_differs_from_subject"] += 1
        p = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in",
                            path], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL)
        text = p.stdout.decode("utf-8", "replace")
        for needle, key in (("prime256v1", "curve_p256"),
                            ("secp384r1", "curve_p384"),
                            ("secp521r1", "curve_p521")):
            if needle in text:
                counts[key] += 1
    finally:
        os.unlink(path)


def folds(counts, mf):
    """Continuation lines in a manifest, and the two awkward shapes.

    A continuation is a physical line beginning with a space. The two
    worth counting are the one whose next byte is also a space, which a
    reader stripping whitespace loses, and the one whose preceding line
    ends part way through a UTF-8 sequence, which a reader decoding line
    by line cannot put back together.
    """
    lines = mf.split(b"\r\n")
    prev = None
    for line in lines:
        if line.startswith(b" "):
            counts["fold_continuation"] += 1
            if line[1:2] == b" ":
                counts["fold_space_after_marker"] += 1
            if prev is not None and incomplete_utf8(prev):
                counts["fold_splits_utf8"] += 1
        prev = line


def incomplete_utf8(b):
    try:
        b.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


def extra_ids(extra):
    out = []
    p = 0
    while p + 4 <= len(extra):
        hid, hlen = struct.unpack("<HH", extra[p:p + 4])
        out.append((hid, extra[p + 4:p + 4 + hlen]))
        p += 4 + hlen
    return out


sys.exit(main())
