import java.io.*;

/**
   IOStream is an efficient buffer for processing a data stream.  You ask
   for a chunk of bytes at a time and IOStream presents them as a subarray
   of a byte array buffer.
   
   IOStream io = new IOStream(...)
   while(...) {
     int p = io.process(n);
     // modify io.buf[p] through io.buf[p+n-1] however you'd like
   }
   io.close();

   You must guarantee that at least n bytes are available on the input stream
   to call process(n).
 */
class IOStream {
  private InputStream in;
  private OutputStream out;
  
  // buf[0,pos) contains data that is already processed and should be written to the output stream.
  // buf[pos,end) contains data yet to be processed from the input stream.
  public byte[] buf;
  private int pos;
  private int end;
  
  // effective current offset in the input/output streams
  public long offset;
  
  IOStream(InputStream in, OutputStream out) {
    this.in = in;
    this.out = out;
    buf = new byte[65536];
  }
  
  /** Transfer a bunch of data from input to output stream.  Returns an index
      into buf where the data is placed so that the caller can subsequently modify it. */
  public int process(int size) throws IOException {
    offset += size;
    
    // make sure our buffer is big enough
    while (size > buf.length) {
      byte[] newbuf = new byte[buf.length * 2];
      System.arraycopy(buf, 0, newbuf, 0, buf.length);
      buf = newbuf;
    }
    
    // if we don't have enough data to process, get some more
    if (end - pos < size) {
      // write out any pending output data
      if (pos > 0) out.write(buf, 0, pos);
      
      // move any pending input data to the front of the buffer
      System.arraycopy(buf, pos, buf, 0, end - pos);
      end -= pos;
      pos = 0;
      
      // refill buffer
      while (end < size) {
        int n = in.read(buf, end, buf.length - end);
        if (n < 0) throw new EOFException("requested block extends beyond EOF");
        end += n;
      }
    }
    
    // return old position, bump position up by the size we read
    assert pos + size <= end;
    int r = pos;
    pos += size;
    return r;
  }
  
  /** Transfer a bunch of data unaltered from input to output stream. */
  public void skip(long size) throws IOException {
    offset += size;
    
    if (pos + size <= end) {
      pos += size;
    } else {
      out.write(buf, 0, end);
      size -= end - pos;
      while (size > 0) {
        int n = in.read(buf);
        if (n < 0) throw new EOFException("requested skip extends beyond EOF");
        if (size <= n) {
          pos = (int)size;
          end = n;
          break;
        }
        out.write(buf, 0, n);
        size -= n;
      }
    }
  }
  
  public void close() throws IOException {
    if (pos > 0) out.write(buf, 0, pos);
    in.close();
    out.close();
  }
}
