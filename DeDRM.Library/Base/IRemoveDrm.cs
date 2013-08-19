using System;
using System.IO;

namespace DeDRM.Library.Base
{
    interface IRemoveDrm
    {
        void OpenFile(String inputFile);
        Boolean DetectDrm(out Constants.DRMType drmType);
        void RemoveDrm(String outputFile);
    }
}
