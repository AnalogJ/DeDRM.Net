import java.util.*;
import java.util.logging.*;
import java.io.*;

class ExtractKeys {
  private static final Logger log = Logger.getLogger(ExtractKeys.class.getName());

  private static void extractKeys(byte[] sidb, byte[] sidd, int userId) throws Exception {
    int sidb_version = (sidb[0]<<24)+((sidb[1]&0xff)<<16)+((sidb[2]&0xff)<<8)+(sidb[3]&0xff);
    log.info("sidb version " + Integer.toHexString(sidb_version));
    if (sidb_version > 0x70009) throw new RuntimeException("key store version too new.  You need a newer version of Requiem");
    if (sidb_version < 0x70008) throw new RuntimeException("key store version too old.  You need a newer version of iTunes");
    int sidd_version = (sidd[0]<<24)+((sidd[1]&0xff)<<16)+((sidd[2]&0xff)<<8)+(sidd[3]&0xff);
    log.info("sidd version " + Integer.toHexString(sidd_version));
    // TODO: need to check sidd version?
    
    // get static data out of jar into temporary files
    File corefp,corefp1,icxs,icxs1;
    if (System.getProperty("os.name").equals("Mac OS X")) {
      corefp = Util.extractStream(ExtractKeys.class.getResourceAsStream("CoreFP-1.13.35.x86"), "corefp");
      corefp1 = Util.extractStream(ExtractKeys.class.getResourceAsStream("CoreFP1-1.13.35.x86"), "corefp1");
      icxs = Util.extractStream(ExtractKeys.class.getResourceAsStream("CoreFP-1.13.35.icxs"), "icxs");
      icxs1 = Util.extractStream(ExtractKeys.class.getResourceAsStream("CoreFP1-1.13.35.icxs"), "icxs1");
    } else {
      corefp = Util.extractStream(ExtractKeys.class.getResourceAsStream("CoreFPWin-1.13.37.x86"), "corefp");
      corefp1 = new File("");
      icxs = new File("");
      icxs1 = new File("");
    }
    File exec = Util.extractStream(ExtractKeys.class.getResourceAsStream("extractor"), "extractor");
    exec.setExecutable(true);
    
    // put sidb/sidd in temporary files
    File sidbf = Util.extractStream(new ByteArrayInputStream(sidb), "sidb");
    File siddf = Util.extractStream(new ByteArrayInputStream(sidd), "sidd");
    
    // call extraction code
    byte[] macaddr = Config.macAddress();
    log.info("extracting keys for " + Integer.toHexString(userId) + " from iTunes keystore");
    Process p = Runtime.getRuntime().exec(new String[]{exec.toString(), Integer.toHexString(userId), sidbf.toString(), siddf.toString(),
                                                       String.format("%02x%02x%02x%02x%02x%02x", macaddr[0], macaddr[1], macaddr[2], macaddr[3], macaddr[4], macaddr[5]),
                                                       corefp.toString(),
                                                       corefp1.toString(),
                                                       icxs.toString(),
                                                       icxs1.toString()});
    
    // read results
    BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
    while (true) {
      String line = r.readLine();
      if (line.startsWith("KEY ")) {
        String[] parts = line.substring(4).split(" ");
        int keyId = Integer.parseInt(parts[0], 16);
        byte[] key = new byte[16];
        for (int i = 0; i < 16; i++) key[i] = (byte)Integer.parseInt(parts[i + 1], 16);
        KeyCache.addKey(userId, keyId, key, 'P');
      } else if (line.startsWith("NOKEY ")) {
        int keyId = Integer.parseInt(line.substring(6), 16);
        KeyCache.noKey(userId, keyId);
      } else if (line.startsWith("ERROR ")) {
        log.severe(line.substring(6));
      } else {
        log.info(line);
      }
      if (line.equals("leaving native code")) break;
    }
    r.close();
    p.waitFor();
    
    // delete all of the temporary files
    corefp.delete();
    if (System.getProperty("os.name").equals("Mac OS X")) {
      corefp1.delete();
      icxs.delete();
      icxs1.delete();
    }
    sidbf.delete();
    siddf.delete();
    exec.delete();
    if (p.exitValue() != 0) {
      throw new RuntimeException("extraction subprocess failed " + p.exitValue());
    }
    log.info("extracted keys from iTunes keystore");
  }
  
  private static HashSet<Integer> tried_users = new HashSet<Integer>();
  
  static void extractKeys(int userId, Notifier notifier) throws Exception {
    if (tried_users.contains(userId)) return;
    tried_users.add(userId);
    byte[] sidb = Util.read(Config.sidb());
    byte[] sidd = Util.read(Config.sidd());
    extractKeys(sidb, sidd, userId);
    // TODO: handle errors, pass to notifier
  }
  
  public static void main(String[] args) throws Exception {
    if (args.length == 1) {
      args = new String[]{Config.sidb(), Config.sidd(), args[0]};
    }
    byte[] sidb = Util.read(args[0]);
    byte[] sidd = Util.read(args[1]);
    extractKeys(sidb, sidd, Integer.parseInt(args[2], 16));
  }
}
