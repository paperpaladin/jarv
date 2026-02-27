#!/usr/bin/env python3
"""Check jarv's manifest work against things outside jarv.

Four authorities, none of them jarv:

  coreutils sha1sum/sha256sum/sha384sum/sha512sum/md5sum over the bytes
  Info-ZIP's unzip -p produces, for every per-entry digest the manifest
  declares.

  coreutils base64 -d, for every base64 value jarv decodes.

  jarsigner itself, indirectly but strictly: it wrote the per-section
  digests in the .SF, so the byte range jarv digests a manifest section
  over is right only if the result equals the number jarsigner put there.
  That is the check on the fold boundaries and on the blank line, and
  nothing jarv computes is compared against anything else jarv computes.

  python3's zipfile, for entry contents whose names Info-ZIP cannot spell.

Usage: mfcmp.py JARV clean|dirty JAR...
"""
import hashlib
import subprocess
import sys
import zipfile

PASS = 0
FAIL = 0
MISMATCH = 0

SUMS = {"SHA-1": "sha1sum", "SHA-224": "sha224sum", "SHA-256": "sha256sum",
        "SHA-384": "sha384sum", "SHA-512": "sha512sum", "MD5": "md5sum"}
PYALG = {"SHA-1": "sha1", "SHA-224": "sha224", "SHA-256": "sha256",
         "SHA-384": "sha384", "SHA-512": "sha512", "MD5": "md5"}


def ok(m):
    global PASS
    PASS += 1
    print("ok   " + m)


def bad(m):
    global FAIL
    FAIL += 1
    print("FAIL " + m)


def run(cmd, stdin=None):
    p = subprocess.run(cmd, input=stdin, stdout=subprocess.PIPE,
                       stderr=subprocess.DEVNULL)
    return p.returncode, p.stdout


def coreutils_digest(jar, name, alg):
    """unzip -p piped into the matching coreutils tool. ASCII names only."""
    tool = SUMS.get(alg)
    if tool is None:
        return None
    p1 = subprocess.Popen(["unzip", "-p", jar, name], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL)
    p2 = subprocess.Popen([tool], stdin=p1.stdout, stdout=subprocess.PIPE)
    p1.stdout.close()
    out = p2.communicate()[0].decode()
    # An extractor that failed still feeds the digest tool an empty stream,
    # and the digest of nothing is a perfectly good-looking hex string. It
    # cost four invented failures on the decoy archive before this check
    # existed, every one of them reported as the digest of an empty file.
    if p1.wait() != 0:
        return None
    return out.split()[0] if out else None


def parse(text):
    rows = []
    for line in text.splitlines():
        f = line.split(" ")
        if not f:
            continue
        kind = f[0]
        kv = {}
        rest = []
        for tok in f[1:]:
            if "=" in tok and tok.split("=", 1)[0].isalpha():
                k, v = tok.split("=", 1)
                kv[k] = v
            else:
                rest.append(tok)
        rows.append((kind, kv, rest, line))
    return rows


def check(jarv, mode, jar):
    tag = jar.rsplit("/", 1)[-1]
    rc, out = run([jarv, "--digests", jar])
    rows = parse(out.decode("utf-8", "replace"))
    if not rows:
        try:
            names = zipfile.ZipFile(jar).namelist()
        except Exception:
            names = []
        if any(n.upper().endswith(".SF") for n in names):
            bad("%s --digests printed nothing for a jar with a .SF (exit %d)"
                % (tag, rc))
        else:
            ok("%s has no signature file and no digest claims" % tag)
        return
    try:
        zf = zipfile.ZipFile(jar)
    except Exception:
        zf = None
    seen = set()
    for kind, kv, rest, line in rows:
        if kind == "entrydig":
            alg = rest[0]
            name = line.split(" ", 1)[1].split(" ", 1)[1]
            name = line.rsplit(kv.get("present", "") + " ", 1)[-1]
            name = line.split("present=%s " % kv["present"], 1)[1]
            seen.add(("entry", name))
            # The outside number.
            want = None
            if all(ord(c) < 128 for c in name) and kv["present"] == "1":
                want = coreutils_digest(jar, name, alg)
            if want is None and zf is not None and kv["present"] == "1":
                try:
                    h = hashlib.new(PYALG[alg])
                    h.update(zf.read(name))
                    want = h.hexdigest()
                except Exception:
                    want = None
            if want is None:
                if mode == "clean":
                    bad("%s entry %s: no outside digest available" % (tag, name))
                continue
            global MISMATCH
            if kv["declared"] != kv["computed"]:
                MISMATCH += 1
                print("mismatch %s %s %s" % (tag, name, alg))
            if kv["computed"] != want:
                bad("%s entry %s %s: jarv computed %s, coreutils %s"
                    % (tag, name, alg, kv["computed"], want))
            else:
                ok("%s entry %s %s computed agrees with coreutils"
                   % (tag, name, alg))
            if mode == "clean":
                if kv["declared"] == want:
                    ok("%s entry %s %s manifest value is correct"
                       % (tag, name, alg))
                else:
                    bad("%s entry %s %s: manifest says %s, coreutils %s"
                        % (tag, name, alg, kv["declared"], want))
        elif kind == "mfdig":
            if mode != "clean":
                continue
            if kv["declared"] == kv["whole"]:
                ok("%s %s manifest-wide digest matches jarsigner's" % (tag, rest[1]))
            else:
                bad("%s %s manifest-wide digest: jarsigner %s, jarv %s"
                    % (tag, rest[1], kv["declared"], kv["whole"]))
        elif kind in ("maindig", "sectdig"):
            if mode != "clean":
                continue
            what = "main attributes" if kind == "maindig" else line.rsplit(" ", 1)[1]
            if kv["declared"] == kv["withblank"]:
                ok("%s section digest with blank line matches jarsigner: %s"
                   % (tag, what))
            elif kv["declared"] == kv["noblank"]:
                bad("%s section %s matched only WITHOUT the blank line" % (tag, what))
            else:
                bad("%s section %s: jarsigner %s, jarv %s/%s"
                    % (tag, what, kv["declared"], kv["withblank"], kv["noblank"]))
            if kv["withblank"] == kv["noblank"]:
                bad("%s section %s: the two byte ranges are the same, so the"
                    " blank line question is not being asked" % (tag, what))
            else:
                ok("%s section %s: the blank line changes the digest" % (tag, what))


def b64_check(jarv, jar):
    """coreutils base64 -d against jarv's decoding of the same strings."""
    tag = jar.rsplit("/", 1)[-1]
    rc, out = run([jarv, "--manifest", jar])
    vals = []
    for line in out.decode("utf-8", "replace").splitlines():
        if not line.startswith("attr "):
            continue
        try:
            key, val = line.split(" ", 2)[2].split(": ", 1)
        except ValueError:
            continue
        if "Digest" in key:
            vals.append(val)
    if not vals:
        return
    rc, hx = run([jarv, "--b64"] + vals)
    ours = hx.decode().split()
    if len(ours) != len(vals):
        bad("%s jarv --b64 returned %d lines for %d values"
            % (tag, len(ours), len(vals)))
        return
    n = 0
    for val, got in zip(vals, ours):
        rc, dec = run(["base64", "-d"], stdin=val.encode())
        if rc != 0:
            bad("%s base64 -d refused %r" % (tag, val))
            continue
        if dec.hex() == got:
            n += 1
        else:
            bad("%s base64 jarv=%s coreutils=%s" % (tag, got, dec.hex()))
    if n:
        ok("%s %d base64 values decode as coreutils base64 -d does" % (tag, n))


def main():
    jarv, mode = sys.argv[1], sys.argv[2]
    for jar in sys.argv[3:]:
        check(jarv, mode, jar)
        b64_check(jarv, jar)
    print("MFCMP_MISMATCH %d" % MISMATCH)
    print("MFCMP_PASS %d" % PASS)
    print("MFCMP_FAIL %d" % FAIL)


main()
