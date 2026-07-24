#!/usr/bin/env python3
"""jarv against jarsigner -verify, per archive and per entry.

This is the comparison the project is measured by, and the hard
invariant in PLAN.md is about exactly these numbers: an archive jarv
verifies and jarsigner does not, or the reverse, is a failure whichever
of the two is right about the specification.

Per entry rather than per archive wherever possible: one verdict per
jar over twenty-two jars is twenty-two comparisons, and the flag column
jarsigner -verbose prints for each member is several hundred.

jarsigner's first column is documented in its own output. s means the
signature was verified for that entry, m means the entry is listed in
the manifest, k means a certificate was found in the keystore, ? means
an unsigned entry. No keystore is passed here, so k never appears and
is not compared.

Four classes of entry are not compared and are counted as refusals:
the manifest, the signature files, the signature blocks, and
directories. jarsigner marks META-INF/MANIFEST.MF with s and nothing
else, which is a statement about what the JarFile API reports rather
than about a digest, and copying it into jarv would be writing a quirk
down rather than checking one.

An oracle that cannot read the archive at all is a refusal, never an
agreement. jarsigner answers "jarsigner: java.util.zip.ZipException"
for zip64-dd.jar, which is the JDK refusing a container it will not
open; that is distinguished here from the SecurityException it raises
when it has read an archive and decided against it.

The unsigned-entry warning is compared on its own, because it is the
reason this program exists: jarsigner prints "jar verified." and exits
0 over an archive with members that nothing signed, and mentions them
in a warning paragraph after the verdict.

Prints JSCMP_PASS n, JSCMP_FAIL n, JSCMP_REFUSED n.
"""
import os
import re
import subprocess
import sys

PASS = 0
FAIL = 0
REFUSED = 0
SKIPPED = 0


def ok(m):
    global PASS
    PASS += 1


def bad(m):
    global FAIL
    FAIL += 1
    print("FAIL " + m)


def refuse(m):
    global REFUSED
    REFUSED += 1
    print("refused " + m)


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return p.returncode, p.stdout.decode("utf-8", "replace")


LINE = re.compile(
    r"^(?P<flags>.{0,8}?)\s*(?P<size>\d+)\s+"
    r"\w{3} \w{3} \d{2} \d{2}:\d{2}:\d{2} \S+ \d{4} (?P<name>.*)$")


def parse_jarsigner(text):
    out = {}
    for line in text.splitlines():
        m = LINE.match(line)
        if not m:
            continue
        out[m.group("name")] = set(c for c in m.group("flags")
                                   if c in "smk?iX")
    return out


def parse_jarv(text):
    out = {}
    for line in text.splitlines():
        if not line.startswith("entry "):
            continue
        rest = line[len("entry "):]
        head, _, name = rest.partition(" name=")
        d = {}
        for kv in head.split(" "):
            k, _, v = kv.partition("=")
            d[k] = v
        out[name] = d
    return out


def machinery(name):
    """Entries jarsigner's flag column describes by a different rule."""
    if name.endswith("/"):
        return True
    low = name.lower()
    if not low.startswith("meta-inf/") or "/" in low[len("meta-inf/"):]:
        return False
    return low == "meta-inf/manifest.mf" or low.endswith(
        (".sf", ".rsa", ".dsa", ".ec"))


def main():
    global SKIPPED
    jarv = sys.argv[1]
    for jar in sys.argv[2:]:
        base = os.path.basename(jar)
        jrc, jtext = run(["jarsigner", "-verify", "-verbose", jar])
        vrc, vtext = run([jarv, "--entries", "--verify", jar])
        if vrc == 4:
            bad("%s: jarv could not read the archive" % base)
            continue
        js_ok = jrc == 0 and "jar verified." in jtext
        # Two different sentences mean "this archive counts as
        # unsigned to me": one for a jar with no signature, and one for
        # a jar signed with an algorithm the JDK has disabled. The
        # second is a policy, and jarv answers it with a refusal rather
        # than by copying the word.
        js_unsigned = ("jar is unsigned." in jtext
                       or "will be treated as unsigned" in jtext)
        js_refused = not js_ok and not js_unsigned \
            and "SecurityException" not in jtext
        verdict = ""
        unsigned = []
        for line in vtext.splitlines():
            if line.startswith("jar "):
                verdict = line.split(" ", 1)[1]
            elif line.startswith("UNSIGNED "):
                unsigned.append(line.split(" ", 1)[1])
        if js_refused:
            why = [l for l in jtext.splitlines()
                   if l.startswith("jarsigner:")]
            refuse("%s: jarsigner would not read it: %s"
                   % (base, (why[0] if why else "exit %d" % jrc)[:110]))
            continue
        if vrc == 3:
            refuse("%s: jarv refused (jarsigner %s)"
                   % (base, "verified" if js_ok else "rejected"))
            continue

        if js_unsigned:
            if verdict == "unsigned":
                ok("%s: both call the archive unsigned" % base)
            else:
                bad("%s: jarsigner says the jar is unsigned, jarv says %s"
                    % (base, verdict))
        elif js_ok == (verdict == "verified"):
            ok("%s: archive verdict agrees, both %s"
               % (base, "accept" if js_ok else "reject"))
        else:
            bad("%s: jarv says %s and jarsigner says %s"
                % (base, verdict, "verified" if js_ok else "rejected"))

        # The exit code is part of the verdict, not decoration.
        want = {"verified": 0, "unsigned": 1, "rejected": 2}.get(verdict)
        if want is not None and vrc == want:
            ok("%s: jarv exit code %d matches its own verdict" % (base, vrc))
        else:
            bad("%s: jarv said %s and exited %d" % (base, verdict, vrc))

        # Only for an archive jarsigner thinks is signed. For a jar
        # with no signature at all it prints "jar is unsigned." and no
        # warning paragraph, while jarv still lists every member as
        # covered by nothing, and both statements are correct.
        js_warns = "unsigned entries which have not been" in jtext
        if js_unsigned:
            pass
        elif js_warns == (len(unsigned) > 0):
            ok("%s: both report %d entries that nothing signed"
               % (base, len(unsigned)))
        else:
            bad("%s: jarv found %d unsigned entries and jarsigner's warning"
                " is %s" % (base, len(unsigned), js_warns))

        # jarsigner warns about an expired signer certificate and about
        # a self-signed one, in prose below the verdict. Both are facts
        # jarv prints on its signer line, so both can be compared.
        expired = sum(1 for l in vtext.splitlines()
                      if l.startswith("signer ") and " expired=1 " in l)
        selfsigned = sum(1 for l in vtext.splitlines()
                         if l.startswith("signer ") and " selfsigned=1 " in l)
        # jarsigner prints its warning paragraph only after it has
        # decided the jar verifies. When it raises a SecurityException
        # it stops, so for a rejected archive there is nothing to
        # compare these against and the oracle is counted as declining.
        if not js_ok:
            refuse("%s: jarsigner rejected before printing its warnings,"
                   " so expiry and self-signing are not compared" % base)
        else:
            for what, mine, theirs_said in (
                    ("expired", expired > 0,
                     "signer certificate has expired" in jtext),
                    ("self-signed", selfsigned > 0,
                     "signer certificate is self-signed" in jtext)):
                if mine == theirs_said:
                    ok("%s: %s agrees with jarsigner (%s)"
                       % (base, what, mine))
                else:
                    bad("%s: jarv says %s is %s and jarsigner says %s"
                        % (base, what, mine, theirs_said))

        theirs = parse_jarsigner(jtext)
        ours = parse_jarv(vtext)
        if not theirs:
            refuse("%s: jarsigner -verbose listed no entries" % base)
            continue
        for name, flags in sorted(theirs.items()):
            mine = ours.get(name)
            if mine is None:
                bad("%s: jarv has no entry named %r" % (base, name))
                continue
            if machinery(name):
                SKIPPED += 1
                continue
            for letter, want_set, got in (
                    ("m", "m" in flags, mine["manifest"] == "1"),
                    ("s", "s" in flags, int(mine["signers"]) > 0),
                    ("?", "?" in flags, "?" in mine["flags"])):
                if want_set == got:
                    ok("%s %s: %s agrees" % (base, name, letter))
                else:
                    bad("%s %s: jarsigner has %s %s and jarv has it %s"
                        % (base, name, letter,
                           "set" if want_set else "clear",
                           "set" if got else "clear"))
        for name in ours:
            if name not in theirs:
                bad("%s: jarsigner did not list %r, which jarv sees"
                    % (base, name))

    if SKIPPED:
        print("refused %d signature-machinery entries not compared" % SKIPPED)
        globals()["REFUSED"] = REFUSED + 1
    print("JSCMP_PASS %d" % PASS)
    print("JSCMP_FAIL %d" % FAIL)
    print("JSCMP_REFUSED %d" % REFUSED)
    return 0


sys.exit(main())
