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

	public Zip(byte[] file) {
		this.file = file;
		findEocd();
		if (!bad()) {
			readCentral();
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
			entries.add(e);
		}
		if (b.remaining() != 0) {
			fail("central directory has " + b.remaining() + " trailing bytes");
		}
	}

	static String hex32(long v) {
		return String.format("0x%08x", v);
	}
}
