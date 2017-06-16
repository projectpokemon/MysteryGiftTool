using CTRAesEngine;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;

namespace AesEngineTest
{
    [TestClass]
    public class UnitTests
    {
        private static readonly byte[] nistPlaintext =
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
                .ToByteArray();

        private static readonly byte[] nistKey = "2b7e151628aed2a6abf7158809cf4f3c".ToByteArray();

        private byte[] GetBoot9()
        {
            return File.ReadAllBytes("boot9.bin");
        }

        [TestMethod]
        public void TestAesCBC()
        {
            var Engine = new AesEngine(GetBoot9());
            Engine.SelectKeyslot(0x11);
            Engine.SetNormalKey(nistKey);
            Engine.SetIV("000102030405060708090a0b0c0d0e0f".ToByteArray());
            Engine.SetMode(AesMode.CBC);
            byte[] encrypted = Engine.Encrypt(nistPlaintext);
            CollectionAssert.AreEqual(encrypted, "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7".ToByteArray());
            byte[] decrypted = Engine.Decrypt(encrypted);
            CollectionAssert.AreEqual(nistPlaintext, decrypted);
        }

        [TestMethod]
        public void TestAesECB()
        {
            var Engine = new AesEngine(GetBoot9());
            Engine.SelectKeyslot(0x11);
            Engine.SetNormalKey(nistKey);
            Engine.SetMode(AesMode.ECB);
            byte[] encrypted = Engine.Encrypt(nistPlaintext);
            CollectionAssert.AreEqual(encrypted, "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4".ToByteArray());
            byte[] decrypted = Engine.Decrypt(encrypted);
            CollectionAssert.AreEqual(nistPlaintext, decrypted);
        }

        [TestMethod]
        public void TestAesCTR()
        {
            var Engine = new AesEngine(GetBoot9());
            Engine.SelectKeyslot(0x11);
            Engine.SetNormalKey(nistKey);
            Engine.SetIV("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".ToByteArray());
            Engine.SetMode(AesMode.CTR);
            byte[] encrypted = Engine.Encrypt(nistPlaintext);
            CollectionAssert.AreEqual(encrypted, "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee".ToByteArray());
            byte[] decrypted = Engine.Decrypt(encrypted);
            CollectionAssert.AreEqual(nistPlaintext, decrypted);
        }

        [TestMethod]
        public void TestKeyScrambler()
        {
            var Engine = new AesEngine(GetBoot9());
            Engine.SelectKeyslot(0x11);
            Engine.SetMode(AesMode.ECB);
            byte[] knownKey = "EE2EA93B450FFCF4D562FF02040122C8".ToByteArray();
            byte[] knownResult = "44D193F977EC6092388ABFE4D9C73A97".ToByteArray();

            byte[] KeyX = new byte[0x10];
            byte[] KeyY = new byte[0x10];
            Engine.SetKeyX(KeyX);
            Engine.SetKeyY(KeyY);
            Engine.SetIV(new byte[0x10]);
            byte[] firstEncrypted = Engine.Encrypt(new byte[0x10]);
            KeyX[0xF] = 1;
            KeyY[0xF] = 4;
            Engine.SetKeyX(KeyX);
            Engine.SetKeyY(KeyY);
            byte[] secondEncrypted = Engine.Encrypt(new byte[0x10]);
            Engine.SetNormalKey(knownKey);
            byte[] knownEncrypted = Engine.Encrypt(new byte[0x10]);
            CollectionAssert.AreEqual(knownResult, knownEncrypted);
            CollectionAssert.AreEqual(knownResult, firstEncrypted);
            CollectionAssert.AreEqual(knownResult, secondEncrypted);
        }
       
    }
}
