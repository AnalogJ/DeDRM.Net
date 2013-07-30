using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DeDRM.Library.Amazon.Mobi
{
    public class Section {
        public long offset { get; set; }
        public byte flags { get; set; }
        public int val { get; set; }
       
        public Section(ArraySlice slice){
            offset = slice.getLong();
            flags =  slice.getByte();
            val = (slice.getByte() << 16) | (slice.getByte() << 8) | (slice.getByte());
        }
    }
}
