package jarv;

import java.util.ArrayList;
import java.util.List;

/**
 * The zip container, parsed by hand.
 *
 * A zip file is read from its end. The last structure is the end of central
 * directory record, which is 22 bytes plus a comment of up to 65535, so it
 * has to be found by scanning backwards for its signature. Everything else
 * is reached from there.
 */
public final class Zip {
	static final long SIG_EOCD = 0x06054b50L;
	static final long SIG_CEN = 0x02014b50L;
	static final long SIG_LOC = 0x04034b50L;
	static final long SIG_DD = 0x08074b50L;
	static final long SIG_Z64_EOCD = 0x06064b50L;
	static final long SIG_Z64_LOC = 0x07064b50L;

	/** Largest comment the end record can declare. */
	static final int MAX_COMMENT = 0xffff;

	private final byte[] file;
	private String err;

	/** Offset of the end of central directory record. */
	int eocdOff = -1;
	int diskNo;
	int cdDisk;
	int cdCountThisDisk;
	int cdCount;
	long cdSize;
	long cdOff;
	int commentLen;

	private final List<Entry> entries = new ArrayList<Entry>();

	/** Set when a zip64 end of central directory record was used. */
	public boolean zip64Eocd;
	/** Offset of the zip64 end record, or -1. */
	public long z64Off = -1;
	public long z64Total = -1;

	public Zip(byte[] file) {
		this.file = file;
		findEocd();
		if (!bad()) {
			findZip64Eocd();
		}
		if (!bad()) {
			readCentral();
		}
		if (!bad()) {
			readLocals();
		}
	}

	public List<Entry> entries() {
		return entries;
	}

	public boolean bad() {
		return err != null;
	}

	public String error() {
		return err;
	}

	void fail(String why) {
		if (err == null) {
			err = why;
		}
	}

	public byte[] file() {
		return file;
	}

	/**
	 * Scan backwards for the end record signature.
	 *
	 * The scan starts at the last position where a 22-byte record could begin
	 * and runs back at most MAX_COMMENT bytes, because that is the longest
	 * comment the format allows after it. Taking the LAST match rather than
	 * the first found going forwards matters: a zip file stored inside
	 * another zip file contains the inner one's end record, and a forward
	 * scan finds that one.
	 */
	private void findEocd() {
		if (file.length < 22) {
			fail("file is " + file.length + " bytes, shorter than an end record");
			return;
		}
		int start = file.length - 22;
		int stop = Math.max(0, file.length - 22 - MAX_COMMENT);
		for (int i = start; i >= stop; i--) {
			if ((file[i] & 0xff) == 0x50 && (file[i + 1] & 0xff) == 0x4b
					&& (file[i + 2] & 0xff) == 0x05 && (file[i + 3] & 0xff) == 0x06) {
				Buf b = new Buf(file, i, file.length - i);
				b.u32();
				int dn = b.u16();
				int cd = b.u16();
				int here = b.u16();
				int total = b.u16();
				long size = b.u32();
				long off = b.u32();
				int clen = b.u16();
				if (b.bad()) {
					continue;
				}
				// The comment length has to reach exactly the end of the
				// file. Without this check any 0x06054b50 inside compressed
				// data is accepted as the end record.
				if (i + 22 + clen != file.length) {
					continue;
				}
				eocdOff = i;
				diskNo = dn;
				cdDisk = cd;
				cdCountThisDisk = here;
				cdCount = total;
				cdSize = size;
				cdOff = off;
				commentLen = clen;
				return;
			}
		}
		fail("no end of central directory record in the last "
			+ (file.length - stop) + " bytes");
	}

	/**
	 * The zip64 end of central directory locator and record.
	 *
	 * The locator is a fixed 20 bytes immediately before the ordinary end
	 * record, so unlike the end record it does not need scanning for. It
	 * holds the offset of the zip64 end record, which carries 64-bit copies
	 * of every field the 32-bit one truncated.
	 *
	 * The trap: a writer may emit all three structures even when nothing
	 * overflowed, and a writer may also emit a 32-bit end record whose
	 * fields are 0xffff and 0xffffffff placeholders. So the presence of the
	 * locator decides, not the placeholder values, and when the locator is
	 * there its numbers win over the 32-bit ones unconditionally. Preferring
	 * the 32-bit copy whenever it is not a placeholder is the shape that
	 * reads a truncated entry count on an archive written by a tool that
	 * rounds.
	 */
	private void findZip64Eocd() {
		if (eocdOff < 20) {
			return;
		}
		Buf b = new Buf(file, eocdOff - 20, 20);
		if (b.u32() != SIG_Z64_LOC) {
			return;
		}
		b.u32();
		long off = b.u64();
		long disks = b.u32();
		if (b.bad() || off < 0 || off > file.length - 56) {
			fail("zip64 locator points at " + off + " in a " + file.length
				+ " byte file");
			return;
		}
		Buf z = new Buf(file, (int) off, file.length - (int) off);
		if (z.u32() != SIG_Z64_EOCD) {
			fail("zip64 locator points at " + off + ", which is not a zip64"
				+ " end of central directory record");
			return;
		}
		long recSize = z.u64();
		z.u16();
		z.u16();
		long dn = z.u32();
		long cd = z.u32();
		long here = z.u64();
		long total = z.u64();
		long size = z.u64();
		long cdoff = z.u64();
		if (z.bad()) {
			fail("zip64 end record: " + z.error());
			return;
		}
		if (recSize < 44) {
			fail("zip64 end record declares size " + recSize + ", under 44");
			return;
		}
		if (total > Integer.MAX_VALUE || size > Integer.MAX_VALUE
				|| cdoff > Integer.MAX_VALUE) {
			fail("zip64 archive with " + total + " entries and a " + size
				+ " byte directory at " + cdoff + " is beyond this reader");
			return;
		}
		zip64Eocd = true;
		z64Off = off;
		z64Total = total;
		diskNo = (int) dn;
		cdDisk = (int) cd;
		cdCountThisDisk = (int) here;
		cdCount = (int) total;
		cdSize = size;
		cdOff = cdoff;
		if (disks > 1) {
			fail("zip64 locator declares " + disks + " disks");
		}
	}

	/**
	 * Walk the central directory.
	 *
	 * The count in the end record is advice, not a boundary: the loop reads
	 * until the declared size is consumed and then compares what it found
	 * with what was promised. A central directory that declares ten entries
	 * and holds eleven is a real container attack, so the mismatch is kept
	 * rather than hidden by trusting one of the two numbers.
	 */
	private void readCentral() {
		if (cdOff > file.length || cdSize > file.length - cdOff) {
			fail("central directory at " + cdOff + " size " + cdSize
				+ " does not fit in " + file.length + " bytes");
			return;
		}
		Buf b = new Buf(file, (int) cdOff, (int) cdSize);
		while (b.remaining() >= 4) {
			long sig = b.u32();
			if (sig != SIG_CEN) {
				fail("central directory entry " + entries.size() + " at "
					+ b.pos() + " has signature " + hex32(sig));
				return;
			}
			Entry e = new Entry();
			e.versionMade = b.u16();
			e.versionNeeded = b.u16();
			e.flags = b.u16();
			e.method = b.u16();
			e.modTime = b.u16();
			e.modDate = b.u16();
			e.crc = b.u32();
			e.compSize = b.u32();
			e.uncompSize = b.u32();
			int nlen = b.u16();
			int elen = b.u16();
			int clen = b.u16();
			e.diskStart = b.u16();
			e.internalAttrs = b.u16();
			e.externalAttrs = b.u32();
			e.localOff = b.u32();
			e.nameBytes = b.bytes(nlen);
			e.extra = b.bytes(elen);
			e.comment = b.bytes(clen);
			if (b.bad()) {
				fail("central directory entry " + entries.size() + ": " + b.error());
				return;
			}
			e.decodeName();
			Zip64.applyCentral(e);
			entries.add(e);
		}
		if (b.remaining() != 0) {
			fail("central directory has " + b.remaining() + " trailing bytes");
		}
	}

	/**
	 * Read the local header of every entry and fill in dataOff.
	 *
	 * The local header repeats the name, the method and the sizes. The two
	 * copies are allowed to differ in exactly one way: when general purpose
	 * bit 3 is set the local copy of the CRC and both sizes is zero and the
	 * real values follow the data in a descriptor. Any other difference is
	 * recorded, because a reader that takes the name from one copy and the
	 * data from the other can be made to extract a different file from the
	 * one it reported.
	 */
	public void readLocals() {
		for (Entry e : entries) {
			readLocal(e);
			if (bad()) {
				return;
			}
		}
	}

	private void readLocal(Entry e) {
		if (e.localOff < 0 || e.localOff > file.length - 30) {
			fail(e.name + ": local header at " + e.localOff
				+ " is outside the file");
			return;
		}
		Buf b = new Buf(file, (int) e.localOff, file.length - (int) e.localOff);
		long sig = b.u32();
		if (sig != SIG_LOC) {
			fail(e.name + ": local header signature " + hex32(sig));
			return;
		}
		b.u16();
		e.localFlags = b.u16();
		e.localMethod = b.u16();
		b.u16();
		b.u16();
		e.localCrc = b.u32();
		e.localCompSize = b.u32();
		e.localUncompSize = b.u32();
		int nlen = b.u16();
		int elen = b.u16();
		e.localNameBytes = b.bytes(nlen);
		byte[] lextra = b.bytes(elen);
		if (b.bad()) {
			fail(e.name + ": local header: " + b.error());
			return;
		}
		e.dataOff = e.localOff + b.pos();
		e.dataDescriptor = (e.localFlags & 0x0008) != 0;
		Zip64.applyLocal(e, lextra);
		if (e.compSize > file.length - e.dataOff) {
			fail(e.name + ": " + e.compSize + " bytes of data at " + e.dataOff
				+ " run past the end of the file");
			return;
		}
		if (e.dataDescriptor) {
			readDescriptor(e);
		}
	}

	/**
	 * The descriptor after a streamed entry.
	 *
	 * Its signature is optional: APPNOTE says a reader should accept the
	 * four bytes 50 4b 07 08 and should also accept their absence, which
	 * means the descriptor is found by trusting the compressed size from
	 * the central directory and then checking what is there. The zip64 form
	 * is eight bytes per size rather than four, and nothing in the
	 * descriptor says which it is: the entry's zip64 flag decides.
	 */
	private void readDescriptor(Entry e) {
		int off = (int) (e.dataOff + e.compSize);
		if (off < 0 || off > file.length) {
			fail(e.name + ": no room for a data descriptor at " + off);
			return;
		}
		Buf b = new Buf(file, off, file.length - off);
		long first = b.u32();
		if (first == SIG_DD) {
			e.ddSigned = true;
		} else {
			b.seek(0);
		}
		long crc = b.u32();
		long cs;
		long us;
		if (e.zip64) {
			cs = b.u64();
			us = b.u64();
		} else {
			cs = b.u32();
			us = b.u32();
		}
		if (b.bad()) {
			fail(e.name + ": data descriptor: " + b.error());
			return;
		}
		e.ddCrc = crc;
		e.ddCompSize = cs;
		e.ddUncompSize = us;
		e.ddOff = off;
		e.ddLen = b.pos();
	}

	/**
	 * Every way the local header and the central directory can disagree,
	 * as a list of one-line descriptions. Empty means they agree.
	 */
	public java.util.List<String> localMismatches(Entry e) {
		java.util.List<String> out = new ArrayList<String>();
		if (!java.util.Arrays.equals(e.nameBytes, e.localNameBytes)) {
			out.add("name differs: central " + e.name + ", local "
				+ new String(e.localNameBytes, java.nio.charset.StandardCharsets.UTF_8));
		}
		if (e.localMethod != e.method) {
			out.add("method differs: central " + e.method + ", local " + e.localMethod);
		}
		if (e.dataDescriptor) {
			if (e.ddCrc != e.crc) {
				out.add("descriptor crc " + hex32(e.ddCrc) + " against central "
					+ hex32(e.crc));
			}
			if (e.ddCompSize != e.compSize) {
				out.add("descriptor compressed size " + e.ddCompSize
					+ " against central " + e.compSize);
			}
			if (e.ddUncompSize != e.uncompSize) {
				out.add("descriptor uncompressed size " + e.ddUncompSize
					+ " against central " + e.uncompSize);
			}
		} else {
			if (e.localCrc != e.crc) {
				out.add("local crc " + hex32(e.localCrc) + " against central "
					+ hex32(e.crc));
			}
			if (e.localCompSize != e.compSize) {
				out.add("local compressed size " + e.localCompSize
					+ " against central " + e.compSize);
			}
			if (e.localUncompSize != e.uncompSize) {
				out.add("local uncompressed size " + e.localUncompSize
					+ " against central " + e.uncompSize);
			}
		}
		return out;
	}

	static String hex32(long v) {
		return String.format("0x%08x", v);
	}
}
