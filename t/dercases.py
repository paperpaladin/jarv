#!/usr/bin/env python3
"""Crafted DER encodings, accepted or refused, jarv against openssl.

Nothing the JDK signs holds any of these, so the corpus cannot reach the
refusal paths in jarv's decoder. Each case is written to a file and given
to both openssl asn1parse and jarv, and the two accept/reject answers are
compared. openssl is lenient about several BER forms that DER forbids;
where it is, the divergence is listed here with both answers so that a
change in either is a failure.
"""
import os
import subprocess
import sys

# (name, bytes, note)
CASES = [
    ("empty-sequence", bytes([0x30, 0x00]), None),
    ("integer-1", bytes([0x02, 0x01, 0x01]), None),
    ("null", bytes([0x05, 0x00]), None),
    ("oid-rsa", bytes([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                       0x01, 0x01, 0x01]), None),
    ("seq-of-two", bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]),
     None),
    ("long-form-128", bytes([0x04, 0x81, 0x80]) + bytes(128), None),
    ("context-0-cons", bytes([0xa0, 0x03, 0x02, 0x01, 0x05]), None),
    ("high-tag-31", bytes([0x1f, 0x1f, 0x01, 0x00]), None),
    # Refusals. Each is a BER encoding that DER forbids, or malformed.
    ("indefinite-length", bytes([0x30, 0x80, 0x02, 0x01, 0x01, 0x00, 0x00]),
     "BER indefinite length"),
    ("long-form-for-5", bytes([0x02, 0x81, 0x05, 0x01, 0x02, 0x03, 0x04,
                               0x05]), "long form for a length under 128"),
    ("leading-zero-length", bytes([0x02, 0x82, 0x00, 0x05, 0x01, 0x02, 0x03,
                                   0x04, 0x05]), "padded length"),
    ("high-tag-padded", bytes([0x1f, 0x80, 0x1f, 0x01, 0x00]),
     "tag number padded with a zero septet"),
    ("high-tag-for-5", bytes([0x1f, 0x05, 0x01, 0x00]),
     "low tag written in the high form"),
    ("truncated-content", bytes([0x04, 0x05, 0x01, 0x02]), "short content"),
    ("trailing-garbage", bytes([0x05, 0x00, 0xff]), "a byte after the value"),
    ("length-overruns", bytes([0x30, 0x05, 0x02, 0x01, 0x01]), "overrun"),
    ("reserved-length", bytes([0x04, 0xff, 0x01]), "reserved length form"),
    ("empty", b"", "nothing at all"),
    ("oid-padded-arc", bytes([0x06, 0x03, 0x2a, 0x80, 0x01]),
     "an OID arc padded with a zero septet"),
]

# Cases where openssl accepts what jarv refuses, with the reason. openssl
# asn1parse is a BER parser with a DER-ish front end; refusing BER is the
# whole point of a verifier, so jarv is deliberately the stricter one.
# Listed with both answers so a change in either side fails.
LENIENT = {
    "indefinite-length", "long-form-for-5", "leading-zero-length",
    "high-tag-padded", "high-tag-for-5", "oid-padded-arc",
}


def main():
    jarv, work = sys.argv[1], sys.argv[2]
    npass = nfail = 0
    agree = strict = 0
    for name, data, note in CASES:
        path = os.path.join(work, name + ".der")
        open(path, "wb").write(data)
        a = subprocess.run([jarv, "--derfile", path], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL).returncode == 0
        b = subprocess.run(["openssl", "asn1parse", "-inform", "DER", "-in",
                            path], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL).returncode == 0
        if name in LENIENT:
            if a:
                nfail += 1
                print("FAIL der %s: jarv accepted a BER form it should refuse"
                      % name)
            elif not b:
                nfail += 1
                print("FAIL der %s: openssl now refuses it too; the recorded"
                      " divergence is stale" % name)
            else:
                strict += 1
                npass += 1
            continue
        if a == b:
            agree += 1
            npass += 1
        else:
            nfail += 1
            print("FAIL der %s: jarv %s, openssl %s"
                  % (name, "accepted" if a else "refused",
                     "accepted" if b else "refused"))
    print("ok   DER cases: %d agree with openssl asn1parse, %d refused by"
          " jarv as BER and accepted by openssl" % (agree, strict))
    print("DERCASE_PASS %d" % npass)
    print("DERCASE_FAIL %d" % nfail)


main()
