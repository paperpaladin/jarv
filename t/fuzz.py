#!/usr/bin/env python3
"""Truncation and single-byte corruption, against jarsigner.

A verifier reads attacker-controlled bytes by definition, so the first
property is that it never dies. Every run has to end in one of jarv's
own exit codes with no Java stack trace on either stream. An uncaught
exception is not a rejection: it is a verifier that said nothing while
looking as though it said no.

The second property needs an oracle, and jarsigner is asked the same
question about the same mutated file. jarv may refuse where jarsigner
answers, and that is counted as a refusal. What it may not do is
verify an archive jarsigner rejects, or reject one jarsigner verifies.

Truncations are taken at twelfths of the file, so the end of central
directory record, the central directory and the entry data are each
cut in some of them. Corruptions flip the top bit of one byte at a
stride through the file, which reaches the local headers, the entry
data, the manifest, the signature file and the signature block.

Five archives rather than all of them: each case costs two JVM starts
and the suite is already a minute. They cover a plain RSA archive, an
ECDSA one, a zip64 one, a stored-entry one, and one with a member
nothing signed.

Five counts, because the interesting ones are not the total. PASS is
both tools judging and agreeing; MATCHED is both declining, which is
an agreement about what is unjudgeable; REFUSED is exactly one of them
declining, which is nobody agreeing with anybody, and is reported
split by which tool declined; FAIL is both judging
and disagreeing; CRASH counts jarv dying, and is also counted as a
failure.
"""
import os
import subprocess
import sys

PASS = 0
FAIL = 0
REFUSED = 0
REFUSED_JARV = 0
REFUSED_ORACLE = 0
MATCHED = 0
CRASH = 0


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


def judge(jarv, path, tag):
    global PASS, FAIL, REFUSED, REFUSED_JARV, REFUSED_ORACLE, MATCHED, CRASH
    rc, out = run([jarv, "--verify", path])
    if rc not in (0, 1, 2, 3, 4) or "\tat " in out \
            or "Exception in thread" in out:
        CRASH += 1
        FAIL += 1
        print("FAIL %s: jarv exited %d with %r" % (tag, rc, out[:300]))
        return
    verdict = ""
    for line in out.splitlines():
        if line.startswith("jar "):
            verdict = line.split(" ", 1)[1]
    jrc, jout = run(["jarsigner", "-verify", path])
    js_ok = jrc == 0 and "jar verified." in jout
    js_unsigned = ("jar is unsigned." in jout
                   or "will be treated as unsigned" in jout)
    # jarsigner raises a SecurityException when it has read the archive
    # and decided against it. Anything else on the way out is the JDK
    # declining to read the file, which is not a verdict.
    js_refused = not js_ok and not js_unsigned \
        and "SecurityException" not in jout
    if rc == 3 and js_refused:
        # Both declined to judge the file. That is an agreement about
        # what is unjudgeable, and it is the answer for every
        # truncation, since cutting the tail off a zip removes the end
        # of central directory record and neither reader can start.
        MATCHED += 1
        return
    if rc == 3 or js_refused:
        REFUSED += 1
        if rc == 3:
            REFUSED_JARV += 1
        else:
            REFUSED_ORACLE += 1
        return
    if js_unsigned:
        # Both words mean the same thing here: nothing in this archive
        # is covered by a signature jarsigner will act on.
        if verdict in ("unsigned", "rejected"):
            PASS += 1
        else:
            FAIL += 1
            print("FAIL %s: jarsigner treats it as unsigned, jarv says %s"
                  % (tag, verdict))
        return
    if (verdict == "verified") == js_ok:
        PASS += 1
        return
    FAIL += 1
    print("FAIL %s: jarv says %s and jarsigner says %s"
          % (tag, verdict, "verified" if js_ok else "rejected"))


def main():
    jarv = sys.argv[1]
    work = sys.argv[2]
    jars = sys.argv[3:]
    os.makedirs(work, exist_ok=True)
    path = os.path.join(work, "f.jar")
    for jar in jars:
        base = os.path.basename(jar)
        raw = open(jar, "rb").read()
        for num in range(1, 12):
            cut = len(raw) * num // 12
            open(path, "wb").write(raw[:cut])
            judge(jarv, path, "%s truncated to %d" % (base, cut))
        stride = max(1, len(raw) // 12)
        for off in range(0, len(raw), stride):
            b = bytearray(raw)
            b[off] ^= 0x80
            open(path, "wb").write(bytes(b))
            judge(jarv, path, "%s bit flipped at %d" % (base, off))
        # Holes rather than truncations, because a truncation always
        # takes the end of central directory record with it and both
        # readers then refuse before they have looked at anything. A
        # hole leaves the container intact and lands inside a local
        # header, an entry, the manifest, the signature file or the
        # signature block, which is where the interesting verdicts are.
        for off in range(0, len(raw) - 16, stride):
            b = bytearray(raw)
            b[off:off + 16] = b"\x00" * 16
            open(path, "wb").write(bytes(b))
            judge(jarv, path, "%s zeroed 16 bytes at %d" % (base, off))
    print("FUZZ_PASS %d" % PASS)
    print("FUZZ_FAIL %d" % FAIL)
    print("FUZZ_REFUSED %d" % REFUSED)
    print("FUZZ_REFUSED_JARV %d" % REFUSED_JARV)
    print("FUZZ_REFUSED_ORACLE %d" % REFUSED_ORACLE)
    print("FUZZ_MATCHED %d" % MATCHED)
    print("FUZZ_CRASH %d" % CRASH)
    return 0


sys.exit(main())
