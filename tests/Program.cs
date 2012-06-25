using System;

namespace BrandonHaynes.Security.SipHash
    {
    public class Program
        {
        static void Main()
            {
            Tests.TestSpecification();
            Tests.TestEmptyMessage();
            Tests.TestSingleByte();
            Tests.TestSixBytes();
            Tests.TestSevenBytes();
            Tests.TestEightBytes();
            Tests.TestOneMillionBytes();

            for (var blockSize = 1; blockSize < Tests.SpecificationMessage.Length * 2; blockSize++)
                Tests.TestBlockHash(blockSize);

            Console.WriteLine("All passed");
            }
        }
    }
