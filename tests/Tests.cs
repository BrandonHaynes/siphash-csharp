using System;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace BrandonHaynes.Security.SipHash
    {
    public static class Tests
        {
        public static readonly byte[] SpecificationKey = Enumerable.Range(0, 16).Select(i => (byte)i).ToArray();
        public static readonly byte[] SpecificationMessage = Enumerable.Range(0, 15).Select(i => (byte)i).ToArray();

        /***
         * Tests adapted from https://github.com/emboss/siphash-java/blob/master/test/com/github/emboss/siphash/SipHashTest.java
         * Thanks to Martin Bosslet for these, which allowed me to quickly verify (presumable) correct functionality.
        ***/

        public static void TestSpecification()
            {
            using (var hash = new SipHash(SpecificationKey))
                AssertEqual(hash.ComputeHash(SpecificationMessage), 0xa129ca6149be45e5UL);
            }

        public static void TestEmptyMessage()
            {
            var message = new byte[0];

            using (var hash = new SipHash(SpecificationKey))
                AssertEqual(hash.ComputeHash(message), 0x726fdb47dd0e0e31UL);
            }

        public static void TestSingleByte()
            {
            var message = new byte[] { 0x61 };

            using (var hash = new SipHash(SpecificationKey))
                AssertEqual(hash.ComputeHash(message), 0x2ba3e8e9a71148caUL);
            }

        public static void TestSixBytes()
            {
            var message = Encoding.UTF8.GetBytes("abcdef");

            using (var hash = new SipHash(SpecificationKey))
                AssertEqual(hash.ComputeHash(message), 0x2a6e77e733c7c05dUL);
            }

        public static void TestSevenBytes()
            {
            var message = Encoding.UTF8.GetBytes("SipHash");

            using (var hash = new SipHash(SpecificationKey))
                AssertEqual(hash.ComputeHash(message), 0x8325093242a96f60UL);
            }

        public static void TestEightBytes()
            {
            var message = Encoding.UTF8.GetBytes("12345678");

            using (var hash = new SipHash(SpecificationKey))
                AssertEqual(hash.ComputeHash(message), 0x2130609caea37ebUL);
            }

        public static void TestOneMillionBytes()
            {
            var message = Enumerable.Repeat((byte)0, 1000000).ToArray();

            using (var hash = new SipHash(SpecificationKey))
                AssertEqual(hash.ComputeHash(message), 0x28205108397aa742UL);
            }

        public static void TestBlockHash(int blockSize)
            {
            using (var hash = new SipHash(SpecificationKey))
                AssertEqual(BlockHash(hash, SpecificationMessage, 0, blockSize), 0xa129ca6149be45e5UL);
            }

        private static byte[] BlockHash(HashAlgorithm hash, byte[] message, int offset, int blockSize)
            {
            if (message.Length - offset >= blockSize)
                {
                var newOffset = hash.TransformBlock(message, offset, blockSize, message, offset);
                return BlockHash(hash, message, offset + newOffset, blockSize);
                }
            else
                {
                hash.TransformFinalBlock(message, offset, message.Length - offset);
                return hash.Hash;
                }
            }

        private static void AssertEqual(byte[] value, ulong expected)
            { Debug.Assert(BitConverter.ToUInt64(value, 0) == expected); }
        }
    }