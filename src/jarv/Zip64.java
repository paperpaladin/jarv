package jarv;

/**
 * The zip64 extended information extra field, header id 0x0001.
 *
 * The trap here is that the field is not a fixed layout. It holds only the
 * values that overflowed their 32-bit slot, in a fixed ORDER but with no
 * tags: uncompressed size, compressed size, local header offset, disk start
 * number. A reader that always reads all four, or reads them in the wrong
 * order, gets plausible garbage rather than an error, because every value
 * is an unsigned 64-bit integer and any eight bytes decode as one.
 *
 * A value is present only if its 32-bit slot held 0xffffffff.
 */
final class Zip64 {
	private Zip64() {
	}

	static final int ID = 0x0001;
	static final long MAX32 = 0xffffffffL;

	/** Apply the central directory copy of the field to an entry. */
	static void applyCentral(Entry e) {
		byte[] ex = e.extra;
		int p = 0;
		while (p + 4 <= ex.length) {
			int id = (ex[p] & 0xff) | ((ex[p + 1] & 0xff) << 8);
			int len = (ex[p + 2] & 0xff) | ((ex[p + 3] & 0xff) << 8);
			p += 4;
			if (len > ex.length - p) {
				return;
			}
			if (id == ID) {
				Buf b = new Buf(ex, p, len);
				if (e.uncompSize == MAX32) {
					e.uncompSize = b.u64();
					e.zip64 = true;
				}
				if (e.compSize == MAX32) {
					e.compSize = b.u64();
					e.zip64 = true;
				}
				if (e.localOff == MAX32) {
					e.localOff = b.u64();
					e.zip64 = true;
				}
				if (e.diskStart == 0xffff && b.remaining() >= 4) {
					e.diskStart = (int) b.u32();
					e.zip64 = true;
				}
				return;
			}
			p += len;
		}
	}

	/**
	 * Apply the local header copy.
	 *
	 * The local copy has a different rule from the central one, and this is
	 * the part readers get wrong: APPNOTE says the local field, when
	 * present, holds BOTH sizes, unconditionally, whether or not either
	 * overflowed. Only the central copy is the sparse one.
	 */
	static void applyLocal(Entry e, byte[] ex) {
		int p = 0;
		while (p + 4 <= ex.length) {
			int id = (ex[p] & 0xff) | ((ex[p + 1] & 0xff) << 8);
			int len = (ex[p + 2] & 0xff) | ((ex[p + 3] & 0xff) << 8);
			p += 4;
			if (len > ex.length - p) {
				return;
			}
			if (id == ID && len >= 16) {
				Buf b = new Buf(ex, p, len);
				e.localUncompSize = b.u64();
				e.localCompSize = b.u64();
				e.zip64 = true;
				return;
			}
			p += len;
		}
	}
}
