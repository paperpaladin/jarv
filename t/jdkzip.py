#!/usr/bin/env python3
"""jarv --zip against java.util.zip.ZipFile.

The weakest of the container oracles and labelled as such in PLAN.md:
it ships with jarsigner, so it is a second opinion rather than an
independent one. Info-ZIP does the real work in zipcmp.py.

It earns its place on the archives where readers disagree, because
those are the files where a verifier's answer depends on which reader
is underneath it. The disagreement in this corpus turned out not to be
the one expected: java.util.zip.ZipFile opens all 25 archives,
including the one jarsigner refuses, so the two halves of the same
library answer differently about zip64-dd.jar. That is asserted, and a
corpus in which nothing separates the JDK's streaming reader from its
random-access one would turn this file red rather than let it repeat
Info-ZIP silently.

Per entry: the uncompressed size, the compressed size, the CRC, the
method, and how many bytes actually came out of the stream. The last
one is the only fact here that makes the JDK decompress, and jarv's
own figure for it comes from its own inflate path.

Prints JDKZIP_PASS n, JDKZIP_FAIL n, JDKZIP_REFUSED n.
"""
import os
import subprocess
import sys

PASS = 0
FAIL = 0
REFUSED = 0


def ok(m):
    global PASS
    PASS += 1


def bad(m):
    global FAIL
    FAIL += 1
    print("FAIL " + m)


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def parse_kv(line, prefix):
    rest = line[len(prefix):]
    head, _, name = rest.partition(" name=")
    d = {}
    for kv in head.split(" "):
        k, _, v = kv.partition("=")
        d[k] = v
    return name, d


def main():
    global REFUSED
    jarv = sys.argv[1]
    probe = sys.argv[2]
    jars = sys.argv[3:]
    refused = []
    for jar in jars:
        base = os.path.basename(jar)
        rc, out = run(["java", "-cp", probe, "ZipProbe", jar])
        if "jdkrefused" in out:
            why = [l for l in out.splitlines() if l.startswith("jdkrefused")]
            refused.append(base)
            REFUSED += 1
            print("refused %s: java.util.zip will not open it, %s"
                  % (base, why[0].split(" ")[1]))
            continue
        theirs = {}
        for line in out.splitlines():
            if line.startswith("jdkentry "):
                name, d = parse_kv(line, "jdkentry ")
                theirs[name] = d
        rc, out = run([jarv, "--zip", jar])
        mine = {}
        for line in out.splitlines():
            if not line.startswith("cen "):
                continue
            name, d = parse_kv(line, "cen ")
            mine[name] = d
        rc, out = run([jarv, "--digest", jar])
        read = {}
        for line in out.splitlines():
            f = line.split(" ", 3)
            if f[0] == "sha256":
                read[f[3]] = f[2]
        if set(theirs) != set(mine):
            bad("%s: the JDK lists %d entries and jarv lists %d"
                % (base, len(theirs), len(mine)))
            continue
        ok("%s: both readers list %d entries" % (base, len(theirs)))
        for name, t in sorted(theirs.items()):
            m = mine[name]
            for what, a, b in (
                    ("usize", int(t["size"]), int(m["usize"])),
                    ("csize", int(t["csize"]), int(m["csize"])),
                    ("crc", t["crc"], m["crc"].lstrip("0x") or "0"),
                    ("method", int(t["method"]), int(m["method"]))):
                if what == "crc":
                    a = t["crc"].lstrip("0") or "0"
                    b = m["crc"].lstrip("0") or "0"
                if a == b:
                    ok("%s %s: %s agrees" % (base, name, what))
                else:
                    bad("%s %s: %s is %r to the JDK and %r to jarv"
                        % (base, name, what, a, b))
            if name in read and int(t["read"]) >= 0:
                if int(t["read"]) == int(t["size"]):
                    ok("%s %s: the JDK read %s bytes out" % (base, name,
                                                             t["read"]))
                else:
                    bad("%s %s: the JDK read %s bytes of a %s-byte entry"
                        % (base, name, t["read"], t["size"]))
    # The JDK disagreeing with itself, which is the fact worth having
    # here and was not the fact this file was written to look for. Its
    # first version asserted that java.util.zip.ZipFile must refuse at
    # least one archive, on the strength of jarsigner refusing
    # zip64-dd.jar. ZipFile opens all 25. The refusal is in the
    # streaming reader jarsigner uses, not in the random-access one, so
    # the two halves of the same library answer differently about the
    # same file, and the archive that shows it is the one with zip64
    # sizes and data descriptors together.
    disagree = []
    for jar in jars:
        base = os.path.basename(jar)
        if base in refused:
            continue
        jrc, jout = run(["jarsigner", "-verify", jar])
        if "java.util.zip" in jout or "ZipException" in jout:
            disagree.append(base)
    if disagree:
        ok("the JDK contradicts itself on %d archive(s): %s"
           % (len(disagree), ", ".join(disagree)))
        print("refused %s: jarsigner will not read what java.util.zip"
              ".ZipFile opens" % ", ".join(disagree))
        REFUSED += len(disagree)
    else:
        bad("no archive in the corpus separates the JDK's streaming zip"
            " reader from its random-access one, so this oracle is only"
            " repeating Info-ZIP")
    print("JDKZIP_PASS %d" % PASS)
    print("JDKZIP_FAIL %d" % FAIL)
    print("JDKZIP_REFUSED %d" % REFUSED)
    return 0


sys.exit(main())
