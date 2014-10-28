package com.hypersocket.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 *
 * <p>Utility class to write common parameter types to a byte array.</p>
 * @author Lee David Painter
 */
public class ByteArrayWriter
    extends ByteArrayOutputStream {

  /**
   * Contruct an empty writer.
   */
  public ByteArrayWriter() {

  }

  /**
   * Construct a writer with an array size of the length supplied.
   * @param length
   */
  public ByteArrayWriter(int length) {
    super(length);
  }

  /**
   * Get the underlying byte array
   * @return the underlying byte array.
   */
  public byte[] array() {
    return buf;
  }

  /**
   * Move the position of the next byte to be written.
   * @param numBytes
   */
  public void move(int numBytes) {
    count += numBytes;
  }

  /**
   * Write a BigInteger to the array.
   * @param bi
   * @throws IOException
   */
  public void writeBigInteger(BigInteger bi) throws IOException {
    byte[] raw = bi.toByteArray();

    writeInt(raw.length);
    write(raw);
  }
  
  /**
   * Write a boolean value to the array.
   * @param b
   * @throws IOException
   */
  public void writeBoolean(boolean b) {
    write(b ? 1 : 0);
  }

  /**
   * Write a binary string to the array.
   * @param data
   * @throws IOException
   */
  public void writeBinaryString(byte[] data) throws IOException {
	  if(data==null)
		  writeInt(0);
	  else
		  writeBinaryString(data, 0, data.length);
  }

  /**
   * Write a binary string to the array.
   * @param data
   * @param offset
   * @param len
   * @throws IOException
   */
  public void writeBinaryString(byte[] data, int offset, int len) throws
      IOException {
	if(data==null)
		writeInt(0);
	else {
	    writeInt(len);
	    write(data, offset, len);
	}
  }

  public void writeMPINT(BigInteger b) {
    short bytes = (short) ( (b.bitLength() + 7) / 8);
    byte[] raw = b.toByteArray();
    writeShort( (short) b.bitLength());
    if (raw[0] == 0) {
      write(raw, 1, bytes);
    }
    else {
      write(raw, 0, bytes);
    }
  }

  public void writeShort(short s) {
    write( (s >>> 8) & 0xFF);
    write( (s >>> 0) & 0xFF);
  }

  /**
   * Write an integer to the array
   * @param i
   * @throws IOException
   */
  public void writeInt(long i) throws IOException {
    byte[] raw = new byte[4];

    raw[0] = (byte) (i >> 24);
    raw[1] = (byte) (i >> 16);
    raw[2] = (byte) (i >> 8);
    raw[3] = (byte) (i);

    write(raw);
  }

  /**
   * Write an integer to the array.
   * @param i
   * @throws IOException
   */
  public void writeInt(int i) throws IOException {
    byte[] raw = new byte[4];

    raw[0] = (byte) (i >> 24);
    raw[1] = (byte) (i >> 16);
    raw[2] = (byte) (i >> 8);
    raw[3] = (byte) (i);

    write(raw);
  }

  /**
   * Encode an integer into a 4 byte array.
   * @param i
   * @return a byte[4] containing the encoded integer.
   */
  public static byte[] encodeInt(int i) {
    byte[] raw = new byte[4];
    raw[0] = (byte) (i >> 24);
    raw[1] = (byte) (i >> 16);
    raw[2] = (byte) (i >> 8);
    raw[3] = (byte) (i);
    return raw;
  }

  public static void encodeInt(byte[] buf, int off, int i) {
    buf[off++] = (byte) (i >> 24);
    buf[off++] = (byte) (i >> 16);
    buf[off++] = (byte) (i >> 8);
    buf[off] = (byte) (i);
  }

  /**
   * Write a string to the byte array.
   * @param str
   * @throws IOException
   */
    public void writeString(String str) throws IOException {
      writeString(str, ByteArrayReader.getCharsetEncoding());
    }

    /**
     * Write a String to the byte array converting the bytes using the
     * given character set.
     * @param str
     * @param charset
     * @throws IOException
     */
  public void writeString(String str, String charset) throws IOException {

    if (str == null) {
      writeInt(0);
    }
    else {
      byte[] tmp;

      if(ByteArrayReader.encode)
        tmp = str.getBytes(charset);
      else
        tmp = str.getBytes();

      writeInt(tmp.length);
      write(tmp);
    }
  }
  
  public void silentClose() {
	  try {
		close();
	} catch (IOException e) {
	}
  }
  
  public void dispose() {
	  super.buf = null;
  }

}