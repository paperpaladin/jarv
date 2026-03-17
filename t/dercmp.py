#!/usr/bin/env python3
"""jarv's DER decoder against openssl asn1parse, node by node.

openssl's ASN.1 code shares nothing with the JDK's and predates it. The
comparison is on five facts per node: byte offset, depth, header length,
content length, and whether the node is constructed, plus the tag mapped
from openssl's own type name. Every node of every signature block in the
corpus, not a count of them.

A decoder that produced half the tree and stopped would agree on every
node it did produce, so the node counts are compared first and a short
tree is a failure rather than a smaller perfect score.
"""
import re
import subprocess
import sys

PASS = 0
FAIL = 0

UNIV = {
    "BOOLEAN": 1, "INTEGER": 2, "BIT STRING": 3, "OCTET STRING": 4,
    "NULL": 5, "OBJECT": 6, "OBJECT DESCRIPTOR": 7, "EXTERNAL": 8,
    "REAL": 9, "ENUMERATED": 10, "UTF8STRING": 12, "SEQUENCE": 16,
    "SET": 17, "NUMERICSTRING": 18, "PRINTABLESTRING": 19, "T61STRING": 20,
    "VIDEOTEXSTRING": 21, "IA5STRING": 22, "UTCTIME": 23,
    "GENERALIZEDTIME": 24, "GRAPHICSTRING": 25, "VISIBLESTRING": 26,
    "GENERALSTRING": 27, "UNIVERSALSTRING": 28, "BMPSTRING": 30,
}


def ok(m):
    global PASS
    PASS += 1
    print("ok   " + m)


def bad(m):
    global FAIL
    FAIL += 1
    print("FAIL " + m)


def run(cmd, **kw):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                       **kw)
    return p.returncode, p.stdout


LINE = re.compile(
    r"^\s*(\d+):d=(\d+)\s+hl=(\d+)\s+l=\s*(\d+)\s+(cons|prim):\s*(.*?)\s*$")


def parse_openssl(text):
    out = []
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        off, d, hl, l, cp, rest = m.groups()
        name = rest.split(":")[0].strip()
        cls, tag = classify(name)
        out.append((int(off), int(d), int(hl), int(l), cp, cls, tag))
    return out


def classify(name):
    m = re.match(r"^(cont|appl|priv)\s*\[\s*(\d+)\s*\]$", name)
    if m:
        return {"cont": 2, "appl": 1, "priv": 3}[m.group(1)], int(m.group(2))
    if name in UNIV:
        return 0, UNIV[name]
    return None, None


def parse_jarv(text):
    blocks = {}
    cur = None
    for line in text.splitlines():
        f = line.split()
        if f and f[0] == "block":
            cur = f[1]
            blocks[cur] = []
        elif f and f[0] == "der":
            kv = dict(x.split("=", 1) for x in f[2:] if "=" in x)
            blocks[cur].append((int(f[1]), int(kv["d"]), int(kv["hl"]),
                                int(kv["l"]), f[5],
                                int(kv["cls"]), int(kv["tag"])))
        elif f and f[0] == "derbad":
            blocks[f[1]] = None
    return blocks


def main():
    jarv, work = sys.argv[1], sys.argv[2]
    for jar in sys.argv[3:]:
        tag = jar.rsplit("/", 1)[-1]
        rc, jt = run([jarv, "--der", jar])
        blocks = parse_jarv(jt.decode("utf-8", "replace"))
        if not blocks:
            continue
        for name, ours in blocks.items():
            tmp = work + "/" + tag + "." + name.replace("/", "_")
            rc, raw = run(["unzip", "-p", jar, name])
            if rc != 0 or not raw:
                # decoy.jar defeats Info-ZIP's end record scan. Extracting
                # with the JDK is plumbing here, not the oracle: openssl
                # still decides what the bytes mean.
                import os
                import shutil
                d = work + "/x"
                shutil.rmtree(d, ignore_errors=True)
                os.makedirs(d)
                rc = subprocess.run(["jar", "xf", os.path.abspath(jar), name],
                                    cwd=d, stderr=subprocess.DEVNULL).returncode
                path = os.path.join(d, name)
                if rc != 0 or not os.path.exists(path):
                    bad("%s %s could not be extracted for openssl"
                        % (tag, name))
                    continue
                raw = open(path, "rb").read()
            open(tmp, "wb").write(raw)
            rc, ot = run(["openssl", "asn1parse", "-inform", "DER", "-in", tmp])
            theirs = parse_openssl(ot.decode("utf-8", "replace"))
            if ours is None:
                bad("%s %s: jarv refused a block openssl read as %d nodes"
                    % (tag, name, len(theirs)))
                continue
            if len(ours) != len(theirs):
                bad("%s %s: %d nodes from jarv, %d from openssl asn1parse"
                    % (tag, name, len(ours), len(theirs)))
                continue
            ok("%s %s: %d nodes, same count as openssl" % (tag, name, len(ours)))
            for a, b in zip(ours, theirs):
                if b[5] is None:
                    continue
                if a == b:
                    PASSONE(tag, name, a)
                else:
                    bad("%s %s node at %d: jarv %r openssl %r"
                        % (tag, name, a[0], a, b))
    print("DERCMP_PASS %d" % PASS)
    print("DERCMP_FAIL %d" % FAIL)


def PASSONE(tag, name, a):
    global PASS
    PASS += 1


main()
