package jarv;

/**
 * A bounds-checked cursor over a byte array.
 *
 * Every read of a jar file goes through one of these. The error flag is
 * sticky: a caller can decode a whole structure and ask once at the end
 * whether anything fell off the edge, which is what keeps the error paths
 * short enough to be right.
 *
 * Zip is little-endian throughout. DER is big-endian, and the DER decoder
 * reads bytes one at a time rather than through u16/u32, so there is no
 * endianness switch here to get wrong.
 */
public final class Buf {
	private final byte[] a;
	private final int base;
	private final int lim;
	private int p;
	private String err;

	public Buf(byte[] a) {
		this(a, 0, a.length);
	}

	public Buf(byte[] a, int off, int len) {
		if (off < 0 || len < 0 || off > a.length || len > a.length - off) {
			throw new IllegalArgumentException("window outside array");
		}
		this.a = a;
		this.base = off;
		this.lim = off + len;
		this.p = off;
	}

	/** Position relative to the start of this window. */
	public int pos() {
		return p - base;
	}

	public int limit() {
		return lim - base;
	}

	public int remaining() {
		return lim - p;
	}

	public boolean bad() {
		return err != null;
	}

	public String error() {
		return err;
	}

	/** Records the first error seen and leaves later ones alone. */
	public void fail(String why) {
		if (err == null) {
			err = why;
		}
	}

	public void seek(int off) {
		if (off < 0 || off > limit()) {
			fail("seek to " + off + " outside 0.." + limit());
			return;
		}
		p = base + off;
	}

	public void skip(int n) {
		if (n < 0 || n > remaining()) {
			fail("skip of " + n + " with " + remaining() + " left");
			return;
		}
		p += n;
	}

	private boolean need(int n) {
		if (err != null) {
			return false;
		}
		if (n > remaining()) {
			fail("read of " + n + " at " + pos() + " with " + remaining() + " left");
			return false;
		}
		return true;
	}

	public int u8() {
		if (!need(1)) {
			return 0;
		}
		return a[p++] & 0xff;
	}

	public int u16() {
		if (!need(2)) {
			return 0;
		}
		int v = (a[p] & 0xff) | ((a[p + 1] & 0xff) << 8);
		p += 2;
		return v;
	}

	public long u32() {
		if (!need(4)) {
			return 0;
		}
		long v = (a[p] & 0xffL) | ((a[p + 1] & 0xffL) << 8)
			| ((a[p + 2] & 0xffL) << 16) | ((a[p + 3] & 0xffL) << 24);
		p += 4;
		return v;
	}

	public long u64() {
		if (!need(8)) {
			return 0;
		}
		long v = 0;
		for (int i = 7; i >= 0; i--) {
			v = (v << 8) | (a[p + i] & 0xffL);
		}
		p += 8;
		return v;
	}

	/** A copy, because callers keep these past the lifetime of the window. */
	public byte[] bytes(int n) {
		if (!need(n)) {
			return new byte[0];
		}
		byte[] out = new byte[n];
		System.arraycopy(a, p, out, 0, n);
		p += n;
		return out;
	}

	/** The underlying array. Only the zip reader, which owns the whole file. */
	public byte[] array() {
		return a;
	}

	/** Absolute offset in the underlying array of this window's start. */
	public int baseOffset() {
		return base;
	}
}
