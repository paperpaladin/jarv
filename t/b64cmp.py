#!/usr/bin/env python3
"""jarv's base64 decoder against coreutils base64 -d, accept and reject.

The interesting cases are the padded groups. "AB==" and "AA==" both decode
to one zero byte if the decoder ignores the bits left over in the final
sextet, so a lenient decoder gives two spellings of one digest value.
coreutils refuses the non-canonical spelling, and this sweep walks every
character of the alphabet through both the two-pad and the one-pad
position to find out where the two disagree.

Rejects are compared as carefully as accepts: a decoder that says no to
everything agrees with coreutils on half of this list.
"""
import string
import subprocess
import sys

ALPHA = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"

CASES = []
for c in ALPHA:
    CASES.append("A" + c + "==")
    CASES.append("AA" + c + "=")
CASES += ["", "A", "AB", "ABC", "ABCD", "====", "A===", "AB=C", "A=BC",
          "AAAA", "////", "++++", "AAAA====", "AAAAAAAA", "AA==AA==",
          "A!==", "AB C", "-AAA", "AAA=", "AAA", "AAAAA"]


# Where the two outside implementations disagree with each other, jarv has
# to pick one, and the pick is asserted here so that changing it is a test
# failure rather than a quiet drift.
#
#   "AA==AA==": coreutils carries on past the padding, java.util.Base64
#   stops. jarv follows java.util.Base64, because it is jarsigner's
#   decoder and jarsigner is the verdict jarv is measured against.
DIVERGENT = {"AA==AA==": ("0000", "-")}


def main():
    jarv = sys.argv[1]
    probe = sys.argv[2] if len(sys.argv) > 2 else None
    p = subprocess.run([jarv, "--b64"] + CASES, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    ours = p.stdout.decode().split("\n")
    npass = nfail = 0
    accepts = 0
    rejects = 0
    for i, s in enumerate(CASES):
        mine = ours[i] if i < len(ours) else "-"
        q = subprocess.run(["base64", "-d"], input=s.encode(),
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        theirs = q.stdout.hex() if q.returncode == 0 else "-"
        if theirs == "-":
            rejects += 1
        else:
            accepts += 1
        if s in DIVERGENT:
            want_core, want_jdk = DIVERGENT[s]
            if theirs != want_core:
                nfail += 1
                print("FAIL base64 %r: coreutils now gives %s, not %s"
                      % (s, theirs, want_core))
            elif mine != want_jdk:
                nfail += 1
                print("FAIL base64 %r: jarv gives %s, the recorded choice"
                      " is %s" % (s, mine, want_jdk))
            else:
                npass += 1
            continue
        if mine == theirs:
            npass += 1
        else:
            nfail += 1
            print("FAIL base64 %r jarv=%s coreutils=%s" % (s, mine, theirs))
    print("ok   base64: %d strings, %d accepted and %d rejected by both"
          % (npass, accepts, rejects))
    if probe:
        q = subprocess.run(["java", "-cp", probe, "B64Probe"] + CASES,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        lines = q.stdout.decode().splitlines()
        jdkpass = jdkfail = 0
        strict = 0
        for i, s in enumerate(CASES):
            if i >= len(lines):
                break
            mime = lines[i].split(" ")[0]
            mine = ours[i] if i < len(ours) else "-"
            if mine == mime:
                jdkpass += 1
            elif mine == "-" and mime != "-":
                strict += 1
            else:
                jdkfail += 1
                print("FAIL base64 %r jarv=%s java.util.Base64 MIME=%s"
                      % (s, mine, mime))
        print("ok   base64: %d of %d agree with java.util.Base64, %d refused"
              " by jarv and accepted by it, 0 the other way"
              % (jdkpass, len(CASES), strict))
        npass += 1
        nfail += jdkfail
    print("B64CMP_PASS %d" % npass)
    print("B64CMP_FAIL %d" % nfail)


main()
