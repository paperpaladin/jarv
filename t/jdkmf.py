#!/usr/bin/env python3
"""jarv --manifest against java.util.jar.Manifest.

The JDK's own manifest parser, and the one jarsigner writes manifests
with, so it is the authority on what a folded line joins back to. Not
independent of the JDK, but independent of the verification path: it is
asked what the attribute values are and nothing about signatures.

The 72-byte fold is the reason this file exists. A manifest line is
broken at a byte position and the break can land inside a UTF-8
sequence, so a reader that decodes each physical line before joining
them reassembles a different name. The corpus has 23 such folds and 23
more where the byte after the continuation marker is a space, which a
reader stripping whitespace loses. Both are compared here as whole
values, hexed on both sides so that two different notions of the
platform encoding cannot compare equal while differing.

Section names are compared as well as values, because a section name
is itself a folded value: the Name attribute of a 67-byte entry is
folded, and the name is what the digest is looked up by.

Prints JDKMF_PASS n, JDKMF_FAIL n, JDKMF_REFUSED n.
"""
import os
import subprocess
import sys
import zipfile

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


def hexs(s):
    return s.encode("utf-8").hex()


def main():
    global REFUSED
    jarv = sys.argv[1]
    probe = sys.argv[2]
    work = sys.argv[3]
    jars = sys.argv[4:]
    os.makedirs(work, exist_ok=True)
    folded = 0
    for jar in jars:
        base = os.path.basename(jar)
        try:
            with zipfile.ZipFile(jar) as z:
                names = [n for n in z.namelist()
                         if n == "META-INF/MANIFEST.MF"
                         or (n.startswith("META-INF/")
                             and n.endswith(".SF")
                             and "/" not in n[len("META-INF/"):])]
                raws = dict((n, z.read(n)) for n in names)
        except Exception as e:
            REFUSED += 1
            print("refused %s: python zipfile: %s" % (base, e))
            continue

        rc, out = run([jarv, "--manifest", jar])
        # sect lines open a section and attr lines fill it, so the two
        # have to be read in order rather than independently.
        mine = {}
        section = None
        fname = None
        for line in out.splitlines():
            if line.startswith("sect "):
                f = line.split(" ")
                fname = f[1]
                section = line.split(" name=", 1)[1]
                mine.setdefault(fname, {}).setdefault(section, {})
            elif line.startswith("attr ") and section is not None:
                rest = line[len("attr "):]
                f, _, kv = rest.partition(" ")
                key, _, value = kv.partition(": ")
                mine[fname][section][key] = value

        for name, raw in sorted(raws.items()):
            path = os.path.join(work, base + "." + name.replace("/", "_"))
            open(path, "wb").write(raw)
            rc, out = run(["java", "-cp", probe, "ManifestProbe", path])
            if "mfrefused" in out:
                REFUSED += 1
                print("refused %s %s: java.util.jar.Manifest: %s"
                      % (base, name, out.strip().split(" ")[1]))
                continue
            theirs = {}
            for line in out.splitlines():
                if not line.startswith("jdkattr "):
                    continue
                f = line.split(" ", 4)
                sect = f[4]
                theirs.setdefault(sect, {})[f[2]] = f[3]
            ours = mine.get(name, {})
            if set(theirs) != set(ours):
                bad("%s %s: the JDK has %d sections and jarv has %d; "
                    "only in one: %r" % (base, name, len(theirs), len(ours),
                                         sorted(set(theirs) ^ set(ours))[:2]))
                continue
            ok("%s %s: %d sections, same names" % (base, name, len(theirs)))
            for sect, attrs in sorted(theirs.items()):
                if len(sect.encode("utf-8")) + 6 > 72:
                    folded += 1
                for key, want in sorted(attrs.items()):
                    got = ours[sect].get(key)
                    if got is None:
                        bad("%s %s [%s]: jarv has no %s"
                            % (base, name, sect, key))
                    elif hexs(got) == want:
                        ok("%s %s [%s] %s" % (base, name, sect, key))
                    else:
                        bad("%s %s [%s] %s: the JDK has %s and jarv has %s"
                            % (base, name, sect, key, want, hexs(got)))
    if folded == 0:
        bad("no section name in the corpus is long enough to be folded, so"
            " this comparison says nothing about the 72-byte rule")
    else:
        ok("%d folded section names compared" % folded)
    print("JDKMF_PASS %d" % PASS)
    print("JDKMF_FAIL %d" % FAIL)
    print("JDKMF_REFUSED %d" % REFUSED)
    return 0


sys.exit(main())
