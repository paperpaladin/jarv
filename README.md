# jarv

A JAR signature verifier written from scratch in Java. Its own zip reader,
its own manifest parser, its own DER decoder, its own PKCS#7 reader, its own
RSA and ECDSA verification. It calls into the platform for two things and
says so below.

It exists for the part of JAR signing that is not signing. A signature
covers the entries the manifest lists. An entry that is in the archive and
not in the manifest is covered by nothing, extracts like any other member,
and tooling has been quiet about it for a long time: `jarsigner -verify`
over such an archive prints `jar verified.`, exits 0, and mentions the
uncovered members in a warning paragraph further down. jarv prints the same
verdict, because disagreeing with `jarsigner` is this project's definition of
failure, and then prints a line per uncovered entry above the summary.

```
$ jarv --verify added.jar
jar verified
signer 0 sf=META-INF/RSA1.SF block=META-INF/RSA1.RSA sig=ok link=manifest ...
UNSIGNED smuggled.txt is in the archive and in no manifest section
summary entries=21 signable=15 signed=14 partial=0 unsigned=1 uncovered=0 ...
```

Four ways a member can fail to be covered, counted and printed apart because
they are four different statements. UNSIGNED is in the archive and in no
manifest section. UNCOVERED is in the manifest with no working signer behind
it. MISMATCH is in the manifest and digests to something else. PARTIAL is
covered by some signers and not others.

## Building and running

```sh
make            # plain javac, no build system, no dependency
make test       # builds the corpus and runs every comparison
make mutants    # the mutation harness
./jarv --verify FILE.jar
```

Modes: `--zip`, `--manifest`, `--digest`, `--digests`, `--der`, `--pkcs7`,
`--sig`, `--curves`, `--entries`, `--verify`. Everything but the last two is
there so an outside tool can be asked the same question.

Exit codes: 0 verified, 1 unsigned, 2 rejected, 3 refused, 4 unusable input.
A refusal is never a rejection and the two never share a code.

`JARV_NOW` overrides the clock certificate validity is judged against, in
seconds since the epoch.

## The oracles

Nothing in the suite is checked against jarv's own output.

`openssl asn1parse` and `openssl pkcs7 -print` for the signature block,
node by node and field by field. Different vendor, different decade, no
shared code with the JDK. `openssl pkeyutl -verifyrecover` for what an RSA
signature decrypts to, which is the one question that reaches the padding
and the modular exponentiation without involving a digest or any content.
`openssl dgst -verify` for whether the bytes jarv nominates as signed are
the bytes the signature covers. `openssl ecparam -param_enc explicit` for
the curve constants. `openssl x509` and `openssl pkcs12` where a
certificate or a key has to come out of something.

`unzip -l` and `zipinfo -v`, Info-ZIP, for the container. Also unrelated to
the JDK.

`sha1sum`, `sha256sum`, `sha384sum`, `sha512sum` and `base64` from
coreutils, and python3's `hashlib` and `zipfile` inside the comparison
scripts, for digests and for reading archives without jarv.

`jarsigner -verify -verbose -certs` and `keytool -printcert -jarfile`. Same
vendor as the library being replaced, so the weakest in principle, and the
only one that knows what a JAR signature means. Its verdict is the headline
number because nothing else produces one.

`java.util.zip.ZipFile` through a 55-line helper, as a second opinion on the
container only. It ships with `jarsigner`, so it is named here to keep it
from being mistaken for an independent authority.

Python's own RSA arithmetic, `pow(m, d, n)` over the modulus and private
exponent that `openssl rsa -text` prints, for crafting signatures over
chosen encoded messages. `openssl pkeyutl` refuses a 256-byte input to
`-sign` with `rsa_padding_mode:none` and `rsautl -raw` is deprecated, so
doing the arithmetic directly was the shorter path and it also keeps the
crafting out of the openssl code that then judges the result.

## The numbers

Measured by `make test` on 2026-10-21. Every number below is printed by the
suite; the block is its own output, not a transcription.

```
ok   container: 5221 facts agree with Info-ZIP, 0 disagree
ok   container, second opinion: 2546 facts agree with java.util.zip.ZipFile,
     0 disagree, 1 refused
ok   base64: 149 strings, 29 accepted and 120 rejected by both
ok   base64: 37 of 149 agree with java.util.Base64, 112 refused by jarv and
     accepted by it, 0 the other way
ok   manifest: 811 facts agree, 0 disagree
ok   DER: 2876 node facts agree with openssl asn1parse, 0 disagree
ok   DER cases: 13 agree with openssl asn1parse, 7 refused by jarv as BER
     and accepted by openssl
ok   PKCS7: 627 facts agree with openssl and keytool, 0 disagree,
     3 refused by the oracle
ok   curves: 21 constants agree with openssl ecparam, 0 disagree
ok   signatures: 143 facts agree with openssl, 0 disagree, 2 refused
ok   jarsigner: 905 facts agree, 0 disagree, 11 refused
ok   encoded messages: 30 agree with jarsigner, 0 disagree
ok   corruption: 63 agree, 0 disagree, 88 both declined,
     28 one declined (11 jarv, 17 jarsigner), 0 crashes

13551 passed, 0 failed
```

The headline is the `jarsigner` line. 905 facts over 25 archives, compared
per entry rather than per archive wherever `jarsigner` prints something per
entry: for each member, whether it is listed in the manifest, whether a
signature was verified for it, and whether it is marked unsigned; for each
archive, the verdict, jarv's own exit code against its own printed verdict,
whether any signer certificate has expired, whether any is self-signed, and
whether there are members nothing signed. Zero disagreements in either
direction, which is the invariant in PLAN.md.

Refusals are counted apart from agreements everywhere, and a refusal is
never scored as agreement with anybody. The ones in the run above:

- 11 in the `jarsigner` comparison. Four archives are rejected before
  `jarsigner` prints the warning paragraph the expiry and self-signing flags
  come from, so there is nothing to compare those against. Three of those
  four also get no per-entry listing, because it raises a SecurityException
  partway through. One is `zip64-dd.jar`, which it will not open at all. One
  is `dsa.jar`, which jarv refuses by design. One is `sha1.jar`, where the
  two tools disagree about the word rather than the outcome. And one counts
  the 116 entries that are the manifest, the signature files, the signature
  blocks and the directories, which `jarsigner` flags by a rule about the
  JarFile API rather than about a digest.
- 7 in the DER cases: BER encodings that `openssl asn1parse` accepts and
  jarv refuses, listed under what does not work below.
- 3 in the PKCS#7 comparison: `keytool -printcert -jarfile` checks digests
  before it will print a certificate, so it declines on the three archives
  with a broken digest or signature.
- 2 in the signature comparison: `dsa.jar`, and `decoy.jar` which python3's
  `zipfile` will not open because of the decoy end records.
- 1 in the second container opinion: `zip64-dd.jar` again, which
  `java.util.zip.ZipFile` reads and `jarsigner` does not.
- 112 base64 strings jarv refuses and `java.util.Base64` accepts, all of
  them crafted, none of them in any archive.

## What the corpus holds

Built at suite run time into a `mktemp -d` by `t/corpus.sh`, from `keytool`,
`jar`, `jarsigner` and `t/mkzip.py`. No key material is committed. The
keystore, four RSA keys, three EC keys and one DSA key are generated fresh
on every run, with a password read from `/dev/urandom`, and the directory is
deleted when the suite ends.

Counted by `t/constructs.py` with python3's `zipfile`, a raw byte scan and
`openssl`, never by jarv, so a construct jarv cannot see reads as zero here
and turns the suite red. The suite refuses to run if any of these is absent.

```
archives             25     fold_continuation    424
entries             483     fold_space_after_marker 23
zip64_eocd            3     fold_splits_utf8      23
zip64_extra          80     decoy_end_record       1
data_descriptor     307     rsa_block             21
no_data_descriptor  176     ec_block               3
stored              128     dsa_block              1
deflated            355     curve_p256             1
empty_entry          24     curve_p384             1
directory            72     curve_p521             1
archive_comment       2     multi_cert_block       1
utf8_flag           483     issuer_differs_from_subject 1
non_ascii_name       48     two_signature_files    2
name_over_72        120     covered_by_one_sf_only 1
name_exactly_72      24     stale_manifest_digest  1
signature_block      25     sha1_entry_digest      1
signature_file       25     manifest              24
```

The archives, and what each is for:

- `good-rsa`, `good-ec`, `good-sha512`, `ec384`, `ec521`: correctly signed,
  across RSA with three digest sizes and ECDSA on all three NIST prime
  curves.
- `chain`: signed by a leaf that a CA in the same keystore issued, so one
  certificate in the corpus has an issuer that differs from its subject and
  one signature block carries two certificates.
- `tampered`, `bitflip`: one entry edited after signing, by replacement and
  by one flipped bit.
- `sigflip`: one bit flipped in the last byte of the signature block, which
  is the last byte of the encrypted digest.
- `added`: an entry added after signing and absent from the manifest. The
  headline case.
- `partial`: signed, an entry added, signed again by a second signer. The
  new entry is covered by one of two signers, and the first signer's
  whole-manifest digest is stale so its `.SF` is tied to the manifest
  section by section instead.
- `dropped`: an entry removed from the archive and left in the manifest.
- `two-signers`: two signers over the same contents.
- `expired`: signed with a certificate that expired two years ago.
- `dsa`: DSA, which is a declared non-goal. `jarsigner` verifies it and jarv
  refuses it, and the suite asserts both halves.
- `sha1`: entry digests in SHA-1. `jarsigner` signs it and then reports it as
  unsigned; jarv refuses it and names the algorithm.
- `unsigned`: no signature at all.
- `zip64`, `zip64-store`, `zip64-partial`, `zip64-dd`: zip64 end records,
  with the extended information extra field full and sparse, with stored
  entries, and with data descriptors.
- `stored`, `nodd`, `comment`: stored rather than deflated, no data
  descriptors, and an archive comment after the end of central directory
  record.
- `decoy`: two more things that look like an end of central directory
  record, one inside a stored entry before the real one and one in the
  archive comment after it.

Manifest constructs are built deliberately rather than hoped for. Entry
names are chosen so that a `Name: ` line lands at 62, 65, 66, 67, 68 and 72
bytes, which puts the 72-byte fold on each side of the boundary and exactly
on it. One name has a space at the fold, so the continuation line begins
with two spaces and a reader that strips whitespace rather than exactly one
character loses one. One name is 67 bytes of UTF-8 whose fold lands inside a
three-byte character, which a reader that decodes each physical line before
joining cannot reassemble.

## What does not work

Certificate signatures are not verified. jarv builds the chain, orders
it leaf first by matching the DER of each issuer name against a subject
name, finds the self-issued root, and reads the validity dates. It does not
check that the issuer actually signed the subject. `jarsigner` with no
keystore does not either, and prints a warning saying the chain could not be
validated, which the suite compares. A verifier that built chains and never
checked them would be worth nothing against an attacker who can add a
certificate to the block, and jarv is in that position today.

Timestamps are reported and not checked. An RFC 3161 token in the
unauthenticated attributes is counted and its presence printed. Nothing
reads it. This means jarv cannot tell a signature made before a certificate
expired from one made after.

There is no revocation checking: no CRL, no OCSP.

DSA is refused rather than verified. That is deliberate and it is asserted: the corpus has a
DSA archive, `jarsigner` verifies it, and jarv is required to refuse it
cleanly and be counted as having refused.

Five mutants survive. Each is a rule in the code that nothing in the
corpus can make fail, and each is here with the reason rather than with a
plan to get to it.

- The ECDSA digest truncated by byte length rather than by bit length. Over
  the three curves and the five SHA digests in use the two never differ.
  P-521 is the only curve whose order is not a whole number of bytes and no
  digest reaches its 66, so nothing is truncated on it at all.
- `r` compared with `x1` rather than with `x1 mod n`. They differ only when
  `x1` is at least `n`, and `x1` is bounded by `p`. For P-256 the gap is
  about one part in 2^32 and for P-521 about one in 2^262.
- An RSA signature at or above the modulus reduced rather than refused. The
  value would have to fit in the same number of bytes as the modulus, which
  `s + n` does only when `s` happens to be below 2^2048 minus `n`. That is a
  coin flip on a keystore generated fresh every run, and a case that is
  present half the time is worse than one that is absent.
- The eight-byte minimum on the PKCS#1 padding run. No key `jarsigner` will
  produce can violate it: with a 2048-bit modulus the run is 218 bytes for a
  SHA-1 DigestInfo and 170 for SHA-512, and even a 512-bit key leaves 10 for
  SHA-256. It would take a modulus under 500 bits.
- Chain building matched on the printed name instead of on the DER. That is
  the case the code is written against, and every name in the corpus is a
  PrintableString, so the two spellings never diverge. It would take a
  certificate carrying a UTF8String name with the same text as another's
  PrintableString, which `keytool` will not make.

Three further mutants were written and dropped before committing rather than
recorded as survivors, because each was unreachable only because a second
guard covered for it: a certificate appearing twice in one chain, not
stopping at a self-issued certificate, and an attribute carrying several
values. A survivor that exists because two guards overlap says nothing about
the suite.

The DER decoder refuses seven BER encodings openssl accepts. Indefinite
length, non-minimal long-form lengths, padded length octets and padded
object identifier arcs are each refused rather than normalised, because DER
is BER with the ambiguity removed and a signature is a claim about one
sequence of bytes. `openssl asn1parse` accepts all seven. Those are counted
as refusals, not as agreements, and nothing the JDK writes contains one.

Base64 is stricter than both of its oracles, and that costs something.
`java.util.Base64` decodes `AB==` to one zero byte, dropping the low two
bits, which gives 64 spellings of one value; jarv accepts only `AA==`.
Since `jarsigner` uses `java.util.Base64`, a manifest crafted that way
verifies for `jarsigner` and is refused by jarv. 112 of 149 probe strings
are refused by jarv and accepted by the JDK for that reason. They are
counted as refusals. No corpus archive contains one, so this is a
difference on crafted input only.

The suite's total is stable and the per-column numbers in the corruption
sweep are not. The keys cannot be fixed, because nothing here may commit
one, so which column a corrupted archive lands in moves a little from run
to run. Every case counts as one assertion whichever column it lands in,
which is why the total does not move. An earlier version counted only the
agreements and the total drifted by three between two runs of identical
code.

`java.util.zip` is used for two things: `Inflater` for method 8 and
`CRC32` for the check. Writing a deflate decoder was not the point of this
project and there is one in the collection already; writing the container
parse was the point and the container parse is jarv's own. `MessageDigest`
is the other platform call: SHA-2 is not reimplemented here either.

One `BigInteger` dependency matters. `modPow` does the RSA
operation and `modInverse` does the ECDSA one. The padding, the DigestInfo,
the curve arithmetic and the point decoding are all written out, because
those are where verifiers go wrong, but the modular exponentiation itself
is the platform's.

ECDSA point arithmetic is affine, with a modular inverse per addition
and per doubling. That is the slow way. The whole suite spends well under a
second in it and Jacobian coordinates would add a page of code whose bugs
produce wrong answers rather than slow ones. Marked in the source with the
ceiling and the upgrade path.

A signer identified by subject key identifier is refused. Resolving one
means indexing certificates by their key identifier extension, which jarv
does not do. Nothing the JDK produces uses that form.

A block with more than one SignerInfo is refused. Several signers behind
one `.SF` would make the coverage
table ambiguous about which signer a `.SF` belongs to. Refused.

## Defects found in the harness, not in the code

Recorded because they are the ones that nearly got away, and because in this
collection most defects have been in the harness.

The suite was structurally unable to see a verifier that stops verifying.
Deleting the unused-bits handling in `bitString` made every RSA public key
unparseable, so every signature became a refusal, and refusals were being
counted apart from failures exactly as planned. The run stayed green. A
refusal is only honest for something jarv says it does not do, and RSA is
not on that list; a refusal on an RSA or EC signature is a disagreement now,
and the same mutation gives 16 failures.

Two overlapping rules were covered by one case. Digest algorithm parameters
must be NULL, and that NULL must be empty. The crafted case fed them an
INTEGER, which is neither, so deleting either rule left the other to reject
it and the mutation of the first survived. Each rule has a case only it can
reject now, and the second rule had no mutant at all before.

A harness that reads only accept-or-reject scores a crash as a correct
rejection. With the ECDSA range check deleted, `modInverse` throws on a zero
`s`, jarv prints no verdict line, and a reader of yes-or-no counts the
missing line as a no. Every crafted case asserts the verdict text now.

A two-certificate chain was counted as one certificate. `p7cmp.py` split
`openssl pkcs7 -print` on the string `cert:`, and openssl prints that header
once and a `cert_info:` block per certificate. Every archive had exactly one
certificate until `chain.jar`, so the splitter had never been asked a
question it could get wrong.

A question that cannot be asked was asked anyway. `sigcmp.py` requires
`openssl dgst -verify` to accept the bytes jarv nominates as signed, which
is meaningless for an archive whose signature is deliberately broken: the
rejection has two causes and they are indistinguishable from outside. It
reported that jarv had the signed bytes wrong for `sigflip.jar`.

48 rejections were being reported as refusals. An entry the container will
not decompress is an entry whose digest cannot be shown to hold, and the
manifest says it should: that is an answer, not a declining to answer.
`jarsigner` calls every one of them a digest error. The corruption sweep
went from 20 agreements to 68.

Three warnings were compared against archives where the oracle never printed
them. `jarsigner` prints its warning paragraph only after deciding a jar
verifies, so for a rejected archive there is nothing to compare the expiry
and self-signing flags against. jarv was right in all three cases and the
harness was wrong to call them disagreements.

The expected disagreement was not the one that existed. `jdkzip.py` was
written to assert that `java.util.zip.ZipFile` refuses at least one archive,
on the strength of `jarsigner` refusing `zip64-dd.jar`. `ZipFile` opens all
25. The refusal lives in the streaming reader `jarsigner` uses, not in the
random-access one, so the two halves of one library answer differently about
the same file.

## Defects found in jarv

The P-521 group order was wrong. Fourteen extra `ff` bytes, 160 hex digits
where the standard has 132, typed in by hand and read by nothing that could
tell. Every P-521 signature would have been rejected. It surfaced only
because the corpus grew an archive on that curve, and the answer was to give
the curve table an oracle of its own: all six constants per curve against
`openssl ecparam`, plus a check that the generator satisfies the curve
equation, which is the other five held against each other.

A comment in `Ec.java` claimed that truncating a digest by byte length
rather than by bit length would reject valid P-521 signatures. It would not.
Over the three curves and the five SHA digests in use the two truncations
never differ, because P-521 is the only curve whose order is not a whole
number of bytes and no digest reaches its 66. The comment was written from
the shape of the rule rather than from the arithmetic.

## Layout

```
src/jarv/     4039 lines of Java, 17 files, no dependency
t/            4129 lines of harness, python3 standard library only
t/corpus.sh   builds the corpus from keytool, jar, jarsigner and mkzip.py
t/mutants.py  the mutation harness
```

`Zip.java` and `Zip64.java` are the container, `Manifest.java` the manifest
grammar with byte ranges, `Der.java` the decoder, `Pkcs7.java` and
`X509.java` the signature block, `Rsa.java` and `Ec.java` the arithmetic,
`Verify.java` the verdict.
