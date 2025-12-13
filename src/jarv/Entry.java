package jarv;

import java.nio.charset.StandardCharsets;

/** One archive member, as the central directory describes it. */
public final class Entry {
	/** Raw name bytes. The charset depends on flag bit 11, so keep both. */
	public byte[] nameBytes = new byte[0];
	/** Name decoded as UTF-8 if bit 11 is set, otherwise as CP437. */
	public String name = "";
	/** General purpose bit flag from the central directory. */
	public int flags;
	public int method;
	public int modTime;
	public int modDate;
	public long crc;
	public long compSize;
	public long uncompSize;
	public int diskStart;
	public int internalAttrs;
	public long externalAttrs;
	public long localOff;
	public byte[] extra = new byte[0];
	public byte[] comment = new byte[0];
	public int versionMade;
	public int versionNeeded;

	/** Set when any of the four zip64 fields came out of the extra field. */
	public boolean zip64;
	/** Set when the local header declared zero sizes and bit 3 is set. */
	public boolean dataDescriptor;
	/** Offset of the local header's file data, filled in by Zip.readLocal. */
	public long dataOff = -1;
	/** Sizes read from the local header, for comparison with the above. */
	public long localCompSize = -1;
	public long localUncompSize = -1;
	public long localCrc = -1;
	public int localFlags;
	public int localMethod = -1;
	public byte[] localNameBytes = new byte[0];

	/** Data descriptor, present when general purpose bit 3 is set. */
	public boolean ddSigned;
	public long ddCrc = -1;
	public long ddCompSize = -1;
	public long ddUncompSize = -1;
	public long ddOff = -1;
	public int ddLen;

	public boolean utf8Name() {
		return (flags & 0x0800) != 0;
	}

	public boolean encrypted() {
		return (flags & 0x0001) != 0;
	}

	public boolean isDirectory() {
		return name.endsWith("/");
	}

	/**
	 * Decode the name as UTF-8, whatever bit 11 says.
	 *
	 * The format says a name without bit 11 is CP437, and Info-ZIP honours
	 * that. The JDK does not: java.util.zip.ZipCoder uses UTF-8 for every
	 * jar entry name regardless of the flag, and so does the manifest. Since
	 * the question jarv answers is whether a manifest section matches an
	 * archive member, matching the JDK here is the correct choice and
	 * matching Info-ZIP would introduce a disagreement that is about
	 * charsets rather than about signatures. nameBytes keeps the original
	 * so the container comparison can work in bytes.
	 */
	void decodeName() {
		name = new String(nameBytes, StandardCharsets.UTF_8);
	}
}
