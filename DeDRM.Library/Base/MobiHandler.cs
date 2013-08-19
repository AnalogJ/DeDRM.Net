using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DeDRM.Library.Base
{
    public class MobiHandler :IRemoveDrm
    {
        public void OpenFile(string inputFile)
        {
            throw new NotImplementedException();
        }

        public bool DetectDrm(out Constants.DRMType drmType)
        {
            throw new NotImplementedException();
        }

        public void RemoveDrm(string outputFile)
        {
            throw new NotImplementedException();
        }
    }
}
