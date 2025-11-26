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
    out = {"entries": []}
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
        elif f[0] == "cen":
            d = dict(kv.split("=", 1) for kv in f[2:] if "=" in kv)
            # name may contain spaces; it is last and introduced by name=
            name = line.split(" name=", 1)[1]
            out["entries"].append({
                "name": name,
                "flags": int(d["flags"], 16),
                "method": int(d["method"]),
                "crc": int(d["crc"], 16),
                "csize": int(d["csize"]),
                "usize": int(d["usize"]),
                "loff": int(d["loff"]),
                "extra": int(d["extra"]),
            })
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
        if a["name"] != b["name"]:
            bad("%s name jarv=%r zipinfo=%r" % (tag, a["name"], b["name"]))
            continue
        n = a["name"]
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
        if name == a["name"] and size == a["usize"]:
            ok("%s unzip-l %s %d" % (tag, name, size))
        else:
            bad("%s unzip-l jarv=(%s,%d) unzip=(%s,%d)"
                % (tag, a["name"], a["usize"], name, size))


def main():
    jarv_bin = sys.argv[1]
    for jar in sys.argv[2:]:
        tag = jar.rsplit("/", 1)[-1]
        compare(tag, jar, jarv_bin)
    print("ZIPCMP_PASS %d" % PASS)
    print("ZIPCMP_FAIL %d" % FAIL)


main()
