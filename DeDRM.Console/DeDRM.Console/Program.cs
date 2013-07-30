using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DeDRM.Library.Amazon.Mobi;

namespace DeDRM.Console
{
    class Program
    {
        static void Main(string[] args)
        {
            MobiBook book = new MobiBook("C:\\test\\Aesops-Fables.azw");
            System.Console.ReadLine();

        }
    }
}
