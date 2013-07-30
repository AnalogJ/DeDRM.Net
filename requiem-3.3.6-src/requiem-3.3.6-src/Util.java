import java.util.*;
import java.util.zip.*;
import java.io.*;
import java.util.logging.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import org.xml.sax.*;

class Util {
  private static final Logger log = Logger.getLogger(Util.class.getName());
  public static void printBuf(String name, byte[] buf) {
    log.fine(name);
    for (int i = 0; i < buf.length; i += 16) {
      String line = String.format("%08x: ", i);
      for (int j = 0; j < 16; j++) {
        line += i + j < buf.length ? String.format("%02x ", buf[i + j] & 0xff) : "   ";
      }
      line += "  ";
      for (int j = 0; j < 16; j++) {
        line += i + j < buf.length && buf[i + j] >= 0x20 && buf[i + j] < 0x7f ? (char)buf[i + j] : ' ';
      }
      log.fine(line);
    }
  }
  public static byte[] read(File file) throws IOException {
    FileInputStream i = new FileInputStream(file);
    byte[] result = read(i);
    i.close();
    return result;
  }
  public static byte[] read(String file) throws IOException {
    FileInputStream i = new FileInputStream(file);
    byte[] result = read(i);
    i.close();
    return result;
  }
  public static byte[] read(InputStream i) throws IOException {
    return read(i, Integer.MAX_VALUE);
  }
  public static byte[] read(InputStream i, int maxBytes) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    byte[] buf = new byte[Math.min(maxBytes, 4096)];
    while (maxBytes > 0) {
      int c = i.read(buf, 0, Math.min(maxBytes, buf.length));
      if (c < 0) break;
      out.write(buf, 0, c);
      maxBytes -= c;
    }
    return out.toByteArray();
  }
  public static void copy(InputStream in, OutputStream out) throws IOException {
    byte[] buf = new byte[4096];
    while (true) {
      int c = in.read(buf);
      if (c < 0) break;
      out.write(buf, 0, c);
    }
  }
  // loads input stream into a temporary file with the given name.
  // closes the input stream when done.
  public static File extractStream(InputStream in, String name) throws IOException {
    File f = File.createTempFile(name, null);
    OutputStream out = new FileOutputStream(f);
    copy(in, out);
    out.close();
    in.close();
    return f;
  }
  // hacky way of parsing xml
  static String findInString(String data, String pre1, String pre2, String post) {
    int a = data.indexOf(pre1);
    if (a < 0) throw new RuntimeException("couldn't find " + pre1);
    a += pre1.length();
    int b = data.indexOf(pre2, a);
    if (b < 0) throw new RuntimeException("couldn't find " + pre2);
    b += pre2.length();
    int c = data.indexOf(post, b);
    if (c < 0) throw new RuntimeException("couldn't find " + post);
    return data.substring(b, c);
  }
  static byte[] base64decode(String data) throws IOException {
    // strip whitespace
    StringBuilder s = new StringBuilder();
    for (char c : data.toCharArray()) {
      if (!Character.isWhitespace(c)) s.append(c);
    }
    return new sun.misc.BASE64Decoder().decodeBuffer(s.toString());
  }
  static int getInt32(byte[] data, int offset) {
    return ((data[offset+0]&0xff)<<24) + ((data[offset+1]&0xff)<<16) + ((data[offset+2]&0xff)<<8) + (data[offset+3]&0xff);
  }
  static int getInt(byte[] data) {
    int x = 0;
    for (int i = 0; i < data.length; i++) {
      x = (x << 8) + (data[i] & 0xff);
    }
    return x;
  }
  static Document parseXml(InputStream data) {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    try {
      return dbf.newDocumentBuilder().parse(data);
    } catch (ParserConfigurationException e) {
      throw new RuntimeException(e);
    } catch (SAXException e) {
      throw new RuntimeException(e);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
