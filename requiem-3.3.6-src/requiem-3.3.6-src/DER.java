import java.util.*;

class DER {
  public static class Atom {
    int tag;
    int klass;
    int encodedLength;
    List<Atom> children; // non-null if it is a compound object
    byte[] data;         // non-null if it is a primitive object
    Atom(int tag, int klass, int encodedLength) {
      this.tag = tag;
      this.klass = klass;
      this.encodedLength = encodedLength;
    }
    Atom child(int i) {
      return children.get(i);
    }
    void print() {
      print("");
    }
    void print(String prefix) {
      System.out.print(prefix);
      System.out.print(tagCode[tag] + klassCode[klass]);
      if (data != null) {
        System.out.print(":");
        if (tag == 0xc || tag == 0x13) {
          System.out.println(" " + new String(data));
        } else {
          for (int i = 0; i < data.length; i++) {
            System.out.print(String.format(" %02x", data[i] & 0xff));
          }
          System.out.println();
        }
      } else {
        System.out.println();
        for (Atom child : children) {
          child.print(prefix + "  ");
        }
      }
    }
  }
  static Atom parse(byte[] data, int offset) {
    int type = data[offset + 0] & 0xff;
    int klass = (type >> 6) & 3;
    int compound = (type >> 5) & 1;
    int tag = type & 0x1f;
    
    if (tag == 31) throw new RuntimeException("can't handle tag 31");
    
    int len = data[offset + 1] & 0xff; // length of data portion
    int hdr; // length of header
    if (len < 0x80) {
      hdr = 2;
    } else if (len == 0x80) {
      throw new RuntimeException("can't handle indefinite");
    } else if (len == 0x81) {
      len = data[offset + 2] & 0xff;
      hdr = 3;
    } else if (len == 0x82) {
      len = ((data[offset + 2] & 0xff) << 8) + (data[offset + 3] & 0xff);
      hdr = 4;
    } else if (len == 0x83) {
      len = ((data[offset + 2] & 0xff) << 16) + ((data[offset + 3] & 0xff) << 8) + (data[offset + 4] & 0xff);
      hdr = 5;
    } else if (len == 0x84) {
      len = (data[offset + 2] << 24) + ((data[offset + 3] & 0xff) << 16) + ((data[offset + 4] & 0xff) << 8) + (data[offset + 5] & 0xff);
      hdr = 6;
    } else {
      throw new RuntimeException("len too big " + len);
    }
    Atom d = new Atom(tag, klass, hdr + len);
    if (compound == 1) {
      d.children = new ArrayList<Atom>();
      int idx = hdr;
      while (idx < hdr + len) {
        Atom child = parse(data, offset + idx);
        d.children.add(child);
        idx += child.encodedLength;
      }
      if (idx != hdr + len) throw new RuntimeException("idx did not match at end of compound object");
    } else {
      d.data = new byte[len];
      System.arraycopy(data, offset + hdr, d.data, 0, len);
    }
    return d;
  }
  private static String[] klassCode = new String[] {"", "-A", "-C", "-P"};
  private static String[] tagCode = new String[] {
    "EOC",
    "BOOL",
    "INT",
    "BITSTR",
    "OCTSTR",
    "NULL",
    "OBJID",
    "OBJDES",
    "EXT",
    "FLOAT",
    "ENUM",
    "EMBEDPDV",
    "UTF8",
    "RELOID",
    "?0e",
    "?0f",
    "SEQ",
    "SET",
    "NUMSTR",
    "STR",
    "T61STR",
    "VIDSTR",
    "IA5STR",
    "UTCTIME",
    "GENTIME",
    "GRAPHSTR",
    "VISSTR",
    "GENSTR",
    "UNIVSTR",
    "CHRSTR",
    "BMPSTR",
    "?1f",
  };
}
