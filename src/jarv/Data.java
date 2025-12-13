package jarv;

import java.util.zip.CRC32;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

/**
 * Entry contents.
 *
 * This is the one place jarv uses java.util.zip, and it uses two things from
 * it: Inflater for method 8 and CRC32 for the check. Writing a deflate
 * decoder was not the point of this project and there is already one in the
 * collection; writing the container parse was the point, and the container
 * parse above is jarv's own. The README says so in the same words.
 *
 * Inflater is given the exact compressed byte range the container parse
 * worked out, with nowrap set because a zip member is a raw deflate stream
 * with no zlib header. Getting dataOff wrong therefore shows up as a
 * DataFormatException or a CRC mismatch rather than as silently different
 * bytes.
 */
public final class Data {
	private Data() {
	}

	/** Thrown when an entry cannot be produced. Never a RuntimeException. */
	public static final class BadData extends Exception {
		private static final long serialVersionUID = 1L;

		BadData(String why) {
			super(why);
		}
	}

	public static byte[] read(Zip z, Entry e) throws BadData {
		if (e.encrypted()) {
			throw new BadData(e.name + ": encrypted entries are refused");
		}
		if (e.dataOff < 0) {
			throw new BadData(e.name + ": no local header was read");
		}
		if (e.uncompSize > Integer.MAX_VALUE) {
			throw new BadData(e.name + ": " + e.uncompSize + " bytes is more"
				+ " than this reader will hold in memory");
		}
		byte[] file = z.file();
		int off = (int) e.dataOff;
		int len = (int) e.compSize;
		if (off > file.length || len > file.length - off) {
			throw new BadData(e.name + ": data runs past the end of the file");
		}
		byte[] out;
		if (e.method == 0) {
			if (len != e.uncompSize) {
				throw new BadData(e.name + ": stored entry has compressed size "
					+ len + " and uncompressed size " + e.uncompSize);
			}
			out = new byte[len];
			System.arraycopy(file, off, out, 0, len);
		} else if (e.method == 8) {
			out = inflate(e, file, off, len);
		} else {
			throw new BadData(e.name + ": compression method " + e.method
				+ " is not supported");
		}
		CRC32 c = new CRC32();
		c.update(out, 0, out.length);
		if (c.getValue() != e.crc) {
			throw new BadData(e.name + ": CRC is "
				+ String.format("0x%08x", c.getValue()) + ", the directory says "
				+ String.format("0x%08x", e.crc));
		}
		return out;
	}

	private static byte[] inflate(Entry e, byte[] file, int off, int len)
			throws BadData {
		int want = (int) e.uncompSize;
		byte[] out = new byte[want];
		Inflater inf = new Inflater(true);
		try {
			inf.setInput(file, off, len);
			int got = 0;
			while (got < want) {
				int n;
				try {
					n = inf.inflate(out, got, want - got);
				} catch (DataFormatException ex) {
					throw new BadData(e.name + ": deflate stream is malformed: "
						+ ex.getMessage());
				}
				if (n == 0) {
					if (inf.finished() || inf.needsInput() || inf.needsDictionary()) {
						break;
					}
				}
				got += n;
			}
			if (got != want) {
				throw new BadData(e.name + ": inflated to " + got + " bytes, the"
					+ " directory says " + want);
			}
		} finally {
			inf.end();
		}
		return out;
	}
}
