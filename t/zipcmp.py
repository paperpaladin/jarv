#!/usr/bin/env python3
"""Compare jarv --zip against Info-ZIP's zipinfo -v and unzip -l.

Fact by fact, per entry, never by diffing the two texts: the formats share
nothing and a text diff would measure formatting.

Prints one 'ok' or 'FAIL' line per fact compared, then ZIPCMP_PASS n and
ZIPCMP_FAIL n for the shell harness to add up.
"""
import re
import subprocess
import sys

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print("ok   " + msg)


def bad(msg):
    global FAIL
    FAIL += 1
    print("FAIL " + msg)


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def parse_zipinfo(text):
    """zipinfo -v: a block per entry, 'Central directory entry #N'."""
    out = []
    blocks = re.split(r"^Central directory entry #\d+:\s*$", text, flags=re.M)
    header = blocks[0]
    for b in blocks[1:]:
        lines = [l.rstrip() for l in b.splitlines()]
        e = {}
        # The name is the first non-empty line that is not the dashes and not
        # the 'extra bytes preceding' note.
        for l in lines:
            s = l.strip()
            if not s or s.startswith("---"):
                continue
            if s.startswith("There are an extra") or s.startswith("There is an extra"):
                continue
            e["name"] = s
            break
        def grab(label, cast=str):
            for l in lines:
                if label in l:
                    v = l.split(":", 1)[1].strip()
                    return cast(v.split()[0]) if v else None
            return None
        e["loff"] = grab("offset of local header from start of archive", int)
        e["crc"] = grab("32-bit CRC value (hex)", lambda s: int(s, 16))
        e["csize"] = grab("compressed size", int)
        e["usize"] = grab("uncompressed size", int)
        e["extra"] = grab("length of extra field", int)
        e["method"] = grab("compression method")
        e["dd"] = grab("extended local header")
        if "name" in e:
            out.append(e)
    m = re.search(r"central directory contains (\d+) entries", header)
    count = int(m.group(1)) if m else None
    m = re.search(r"The central directory is (\d+) ", header)
    cdsize = int(m.group(1)) if m else None
    m = re.search(r"is (\d+) \(0{10}[0-9A-Fa-f]+h\)\.?\s*$", header, flags=re.M)
    cdoff = int(m.group(1)) if m else None
    m = re.search(r"Actual end-cent-dir record offset:\s+(\d+)", header)
    eocd = int(m.group(1)) if m else None
    return {"entries": out, "count": count, "cdsize": cdsize,
            "cdoff": cdoff, "eocd": eocd}


METHODS = {"none": 0, "stored": 0, "deflated": 8}


def parse_jarv(text):
    out = {"entries": [], "locbad": []}
    for line in text.splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "eocd":
            d = dict(kv.split("=", 1) for kv in f[1:])
            out["eocd"] = int(d["off"])
            out["count"] = int(d["entries"])
            out["cdoff"] = int(d["cdoff"])
            out["cdsize"] = int(d["cdsize"])
            out["zip64"] = int(d["zip64"])
            out["z64off"] = int(d["z64off"])
        elif f[0] == "cen":
            d = dict(kv.split("=", 1) for kv in f[2:] if "=" in kv)
            # name may contain spaces; it is last and introduced by name=
            name = line.split(" name=", 1)[1]
            d.pop("name", None)
            out["entries"].append({
                "name": name,
                "flags": int(d["flags"], 16),
                "method": int(d["method"]),
                "crc": int(d["crc"], 16),
                "csize": int(d["csize"]),
                "usize": int(d["usize"]),
                "loff": int(d["loff"]),
                "extra": int(d["extra"]),
                "namehex": d["namehex"],
            })
        elif f[0] == "loc":
            d = dict(kv.split("=", 1) for kv in f[2:] if "=" in kv)
            out["entries"][int(f[1])].update({
                "dataoff": int(d["dataoff"]),
                "dd": int(d["dd"]),
                "zip64": int(d["zip64"]),
                "mismatch": int(d["mismatch"]),
            })
        elif f[0] == "locbad":
            out["locbad"].append(line)
    return out


def compare(tag, jar, jarv_bin):
    rc, jt = run([jarv_bin, "--zip", jar])
    if rc != 0:
        bad("%s jarv --zip exited %d" % (tag, rc))
        return
    rc, zt = run(["zipinfo", "-v", jar])
    if rc != 0:
        bad("%s zipinfo -v exited %d" % (tag, rc))
        return
    ours = parse_jarv(jt)
    theirs = parse_zipinfo(zt)

    # On a zip64 archive Info-ZIP reports the zip64 end record's offset
    # under "Actual end-cent-dir record offset", not the 32-bit record's.
    # Measured on the corpus: three archives disagreed by exactly the
    # 20-byte locator plus the 56-byte zip64 record.
    if ours.get("zip64"):
        ours = dict(ours, eocd=ours["z64off"])
    for key in ("eocd", "count", "cdoff", "cdsize"):
        a, b = ours.get(key), theirs.get(key)
        if b is None:
            bad("%s %s: zipinfo gave nothing to compare" % (tag, key))
        elif a == b:
            ok("%s eocd.%s %s" % (tag, key, a))
        else:
            bad("%s eocd.%s jarv=%s zipinfo=%s" % (tag, key, a, b))

    if len(ours["entries"]) != len(theirs["entries"]):
        bad("%s entry count jarv=%d zipinfo=%d"
            % (tag, len(ours["entries"]), len(theirs["entries"])))
        return
    for a, b in zip(ours["entries"], theirs["entries"]):
        n = a["name"]
        ascii_name = all(ord(ch) < 128 for ch in n)
        if ascii_name and a["name"] != b["name"]:
            bad("%s name jarv=%r zipinfo=%r" % (tag, a["name"], b["name"]))
            continue
        if not ascii_name:
            # This build of Info-ZIP has no UNICODE_SUPPORT (unzip -v lists
            # the compilation options and it is not among them), so it
            # cannot print a UTF-8 entry name and prints mojibake instead.
            # The name bytes are compared against python3's zipfile below,
            # which is a third independent reader; the rest of this entry's
            # facts are compared here as usual, keyed by position.
            n = "entry#%d" % theirs["entries"].index(b)
        for key in ("loff", "crc", "csize", "usize", "extra"):
            if a[key] == b[key]:
                ok("%s %s.%s %s" % (tag, n, key, a[key]))
            else:
                bad("%s %s.%s jarv=%s zipinfo=%s" % (tag, n, key, a[key], b[key]))
        want = METHODS.get(b["method"])
        if want is None:
            bad("%s %s.method zipinfo said %r, not in the table"
                % (tag, n, b["method"]))
        elif want == a["method"]:
            ok("%s %s.method %s" % (tag, n, b["method"]))
        else:
            bad("%s %s.method jarv=%d zipinfo=%s" % (tag, n, a["method"], b["method"]))
        dd = (a["flags"] & 8) != 0
        theird = b["dd"] == "yes"
        if dd == theird:
            ok("%s %s.datadesc %s" % (tag, n, b["dd"]))
        else:
            bad("%s %s.datadesc jarv=%s zipinfo=%s" % (tag, n, dd, b["dd"]))

    # The local header repeats name, method and sizes. jar and jarsigner
    # write them consistently, so on this corpus every mismatch list must be
    # empty; the tampered cases later are where it is allowed not to be.
    if not ours["locbad"]:
        ok("%s local headers agree with the central directory (%d entries)"
           % (tag, len(ours["entries"])))
    else:
        for l in ours["locbad"]:
            bad("%s %s" % (tag, l))

    # python3's zipfile, on the name bytes, because Info-ZIP cannot show
    # them here. A third reader, written by neither Oracle nor Info-ZIP.
    import zipfile
    try:
        with zipfile.ZipFile(jar) as zf:
            theirnames = [i.orig_filename.encode("utf-8") for i in zf.infolist()]
    except Exception as ex:
        bad("%s python zipfile refused the archive: %s" % (tag, ex))
        theirnames = None
    if theirnames is not None:
        if len(theirnames) != len(ours["entries"]):
            bad("%s python zipfile listed %d entries, jarv %d"
                % (tag, len(theirnames), len(ours["entries"])))
        else:
            for nb, a in zip(theirnames, ours["entries"]):
                if nb.hex() == a["namehex"]:
                    ok("%s namebytes %s" % (tag, a["namehex"][:24]))
                else:
                    bad("%s namebytes jarv=%s zipfile=%s"
                        % (tag, a["namehex"], nb.hex()))

    # unzip -l is a second opinion on names and uncompressed sizes only.
    rc, ut = run(["unzip", "-l", jar])
    if rc != 0:
        bad("%s unzip -l exited %d" % (tag, rc))
        return
    rows = []
    started = False
    for line in ut.splitlines():
        if re.match(r"^\s*-+\s+-+", line):
            started = not started
            continue
        if started:
            m = re.match(r"^\s*(\d+)\s+\S+\s+\S+\s+(.*)$", line)
            if m:
                rows.append((int(m.group(1)), m.group(2)))
    if len(rows) != len(ours["entries"]):
        bad("%s unzip -l listed %d entries, jarv %d"
            % (tag, len(rows), len(ours["entries"])))
        return
    for (size, name), a in zip(rows, ours["entries"]):
        if not all(ord(ch) < 128 for ch in a["name"]):
            continue
        if name == a["name"] and size == a["usize"]:
            ok("%s unzip-l %s %d" % (tag, name, size))
        else:
            bad("%s unzip-l jarv=(%s,%d) unzip=(%s,%d)"
                % (tag, a["name"], a["usize"], name, size))


def digests(tag, jar, jarv_bin):
    """unzip -p extracts, sha256sum digests, jarv has to match both.

    This is the check that dataOff is right. An offset off by one byte makes
    the deflate stream malformed or the CRC wrong, and an offset that is off
    by a whole header produces a different file, which the digest sees and
    a size comparison would not.
    """
    rc, jt = run([jarv_bin, "--digest", jar])
    ours = {}
    order = []
    for line in jt.splitlines():
        f = line.split(" ", 3)
        if len(f) == 4 and f[0] == "sha256":
            ours[f[3]] = (f[1], int(f[2]))
            order.append(f[3])
        elif f and f[0] == "nodata":
            bad("%s digest %s: jarv could not read it: %s"
                % (tag, f[1], " ".join(f[2:])))
    import hashlib
    import zipfile
    try:
        zf = zipfile.ZipFile(jar)
    except Exception:
        zf = None
    for name in order:
        if name.endswith("/"):
            continue
        if zf is not None:
            try:
                want = hashlib.sha256(zf.read(name)).hexdigest()
            except Exception as ex:
                want = "zipfile refused: %s" % ex
            got, size = ours[name]
            if want == got:
                ok("%s pydigest %s %s" % (tag, name, got[:16]))
            else:
                bad("%s pydigest %s jarv=%s python=%s" % (tag, name, got, want))
        if not all(ord(ch) < 128 for ch in name):
            continue
        p1 = subprocess.Popen(["unzip", "-p", jar, name], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL)
        p2 = subprocess.Popen(["sha256sum"], stdin=p1.stdout,
                              stdout=subprocess.PIPE)
        p1.stdout.close()
        out = p2.communicate()[0].decode()
        p1.wait()
        want = out.split()[0] if out else "?"
        got, size = ours[name]
        if want == got:
            ok("%s digest %s %s" % (tag, name, got[:16]))
        else:
            bad("%s digest %s jarv=%s unzip+sha256sum=%s"
                % (tag, name, got, want))


def jartf(tag, jar, jarv_bin):
    """The JDK's own zip reader, through jar tf, on the name list.

    This runs for every archive including the ones Info-ZIP cannot read,
    because the JDK's reader is the one whose agreement decides whether
    jarv and jarsigner are looking at the same archive at all.
    """
    rc, out = run(["jar", "tf", jar])
    if rc != 0:
        bad("%s jar tf exited %d" % (tag, rc))
        return
    theirs = sorted(l for l in out.splitlines() if l)
    rc, jt = run([jarv_bin, "--zip", jar])
    ours = sorted(l.split(" name=", 1)[1] for l in jt.splitlines()
                  if l.startswith("cen "))
    if ours == theirs:
        ok("%s jar tf: %d names agree with the JDK's reader" % (tag, len(ours)))
    else:
        bad("%s jar tf: %d names from the JDK, %d from jarv; first difference %r"
            % (tag, len(theirs), len(ours),
               next((a for a, b in zip(ours + [None] * 9, theirs + [None] * 9)
                     if a != b), None)))


def decoy_divergence(tag, jar, jarv_bin):
    """Three readers, three answers, recorded rather than smoothed over.

    decoy.jar carries a second end of central directory record inside a
    stored entry, placed so that its declared comment length reaches
    exactly the end of the file, and a third one in the archive comment.
    The JDK reads the real record. Info-ZIP takes the last signature it
    finds without checking that the comment reaches the end, so it takes
    the one in the comment and then cannot list the archive. python3's
    zipfile does the same and refuses with "Bad offset for central
    directory". jarv follows the JDK.
    """
    rc, jt = run([jarv_bin, "--zip", jar])
    names = [l.split(" name=", 1)[1] for l in jt.splitlines()
             if l.startswith("cen ")]
    if "META-INF/MANIFEST.MF" in names and len(names) > 5:
        ok("%s jarv found the real central directory (%d entries)"
           % (tag, len(names)))
    else:
        bad("%s jarv found %d entries and %s the manifest; it took a decoy"
            % (tag, len(names),
               "found" if "META-INF/MANIFEST.MF" in names else "missed"))
    rc, _ = run(["unzip", "-l", jar])
    if rc != 0:
        ok("%s unzip -l fails, as recorded" % tag)
    else:
        bad("%s unzip -l now succeeds; the recorded divergence is stale" % tag)
    import zipfile
    try:
        zipfile.ZipFile(jar).namelist()
        bad("%s python zipfile now reads it; the recorded divergence is stale"
            % tag)
    except Exception:
        ok("%s python3 zipfile refuses it, as recorded" % tag)


def main():
    jarv_bin = sys.argv[1]
    for jar in sys.argv[2:]:
        tag = jar.rsplit("/", 1)[-1]
        jartf(tag, jar, jarv_bin)
        if tag == "decoy.jar":
            decoy_divergence(tag, jar, jarv_bin)
            continue
        compare(tag, jar, jarv_bin)
        digests(tag, jar, jarv_bin)
    print("ZIPCMP_PASS %d" % PASS)
    print("ZIPCMP_FAIL %d" % FAIL)


main()
