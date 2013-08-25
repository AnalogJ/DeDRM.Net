using System;
using System.IO;
using Ionic.Zip;

namespace DeDRM.Library.Base
{
    interface IRemoveDrm
    {
        
        void RemoveDrm(String inputZipFilePath, String outputZipFilePath);
    }
}
