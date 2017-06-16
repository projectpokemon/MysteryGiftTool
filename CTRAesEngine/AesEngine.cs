using System;
using System.IO;
using System.Net;
using System.Numerics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace CTRAesEngine
{
    public enum AesMode
    {
        NotSupported = 0,
        CTR = 1,
        CBC = 2,
        ECB = 3
    }
    public class AesEngine
    {
        private byte[][] KeyXs;
        private byte[][] KeyYs;

        private byte[][] NormalKeys;

        private byte[] CTR_IV_NONCE;

        private byte[] MAC;

        private AesMode Mode;

        private int Slot;

        private bool _isdev;

        private byte[] _nandcid;

        private byte[] _boot9;
        private int _boot9_prot_ofs;
        private bool _boot9Valid;

        private byte[] _boot9_hash = ("5ADDF30ECB46C624FA97BF1E83303CE5" +
                                      "D36FABB4525C08C966CBAF0A397FE4C3" +
                                      "3D8A4AD17FD0F4F509F547947779E1B2" +
                                      "DB32ABC0471E785CACB3E2DDE9B8C492").ToByteArray();

        public AesEngine(byte[] boot9)
        {
            _boot9 = boot9;

            KeyXs = new byte[0x40][];
            KeyYs = new byte[0x40][];
            NormalKeys = new byte[0x40][];

            CTR_IV_NONCE = new byte[0x10];
            MAC = new byte[0x10];
            _nandcid = new byte[0x10];

            for (int i = 0; i < NormalKeys.Length; i++)
            {
                KeyXs[i] = new byte[0x10];
                KeyYs[i] = new byte[0x10];
                NormalKeys[i] = new byte[0x10];
            }

            _isdev = false;

            InitializeKeyslots(_boot9);
            Slot = 0;
        }

        public bool IsBootRomLoaded
        {
            get { return _boot9Valid; }
            private set { _boot9Valid = value; }
        }

        public bool IsDev
        {
            get { return _isdev; }
            set { _isdev = value; }
        }

        private Aes CreateAes(byte[] key, byte[] iv, CipherMode mode, PaddingMode padding)
        {
            var aes = Aes.Create();
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = mode;
            aes.Padding = padding;
            return aes;
        }

        public byte[] Encrypt(byte[] input)
        {
            byte[] output = new byte[input.Length];

            byte[] key = (byte[])(NormalKeys[Slot].Clone());
            byte[] ctr_iv_nonce = new byte[0x10];
            CTR_IV_NONCE.CopyTo(ctr_iv_nonce, 0);

            switch (Mode)
            {
                case AesMode.NotSupported:
                    throw new NotSupportedException();
                case AesMode.CBC:
                    using (var _aes = CreateAes(key, ctr_iv_nonce, CipherMode.CBC, PaddingMode.None))
                    {
                        _aes.CreateEncryptor(_aes.Key, _aes.IV).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
                case AesMode.CTR:
                    using (var _aes = new AesCtr(ctr_iv_nonce))
                    {
                        _aes.CreateEncryptor(key).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
                case AesMode.ECB:
                    using (var _aes = CreateAes(key, ctr_iv_nonce, CipherMode.ECB, PaddingMode.None))
                    {
                        _aes.CreateEncryptor(_aes.Key, _aes.IV).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
            }
            return output;
        }

        public void Encrypt(Stream inStream, Stream outStream, long count)
        {
            byte[] key = (byte[])(NormalKeys[Slot].Clone());
            byte[] ctr_iv_nonce = new byte[0x10];
            CTR_IV_NONCE.CopyTo(ctr_iv_nonce, 0);
            switch (Mode)
            {
                case AesMode.NotSupported:
                    throw new NotSupportedException();
                case AesMode.CBC:
                    using (var _aes = CreateAes(key, ctr_iv_nonce, CipherMode.CBC, PaddingMode.None))
                    {
                        using (var encryptor = _aes.CreateEncryptor(_aes.Key, _aes.IV))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                encryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
                case AesMode.CTR:
                    using (var _aes = new AesCtr(ctr_iv_nonce))
                    {
                        using (var encryptor = _aes.CreateEncryptor(key))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                encryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
                case AesMode.ECB:
                    using (var _aes = CreateAes(key, ctr_iv_nonce, CipherMode.ECB, PaddingMode.None))
                    {
                        using (var encryptor = _aes.CreateEncryptor(key, _aes.IV))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                encryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
            }
        }

        public byte[] Decrypt(byte[] input)
        {
            byte[] output = new byte[input.Length];

            byte[] key = (byte[])(NormalKeys[Slot].Clone());
            byte[] ctr_iv_nonce = new byte[0x10];
            CTR_IV_NONCE.CopyTo(ctr_iv_nonce, 0);

            switch (Mode)
            {
                case AesMode.NotSupported:
                    throw new NotSupportedException();
                case AesMode.CBC:
                    using (var _aes = CreateAes(key, ctr_iv_nonce, CipherMode.CBC, PaddingMode.None))
                    {
                        _aes.CreateDecryptor(_aes.Key, _aes.IV).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
                case AesMode.CTR:
                    using (var _aes = new AesCtr(ctr_iv_nonce))
                    {
                        _aes.CreateDecryptor(key).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
                case AesMode.ECB:
                    using (var _aes = CreateAes(key, ctr_iv_nonce, CipherMode.ECB, PaddingMode.None))
                    {
                        _aes.CreateDecryptor(_aes.Key, _aes.IV).TransformBlock(input, 0, input.Length, output, 0);
                    }
                    break;
            }

            return output;
        }

        public void Decrypt(Stream inStream, Stream outStream, long count)
        {
            byte[] key = (byte[])(NormalKeys[Slot].Clone());
            byte[] ctr_iv_nonce = new byte[0x10];
            CTR_IV_NONCE.CopyTo(ctr_iv_nonce, 0);
            switch (Mode)
            {
                case AesMode.NotSupported:
                    throw new NotSupportedException();
                case AesMode.CBC:
                    using (var _aes = CreateAes(key, ctr_iv_nonce, CipherMode.CBC, PaddingMode.None))
                    {
                        using (var decryptor = _aes.CreateDecryptor(_aes.Key, _aes.IV))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                decryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
                case AesMode.CTR:
                    using (var _aes = new AesCtr(ctr_iv_nonce))
                    {
                        using (var decryptor = _aes.CreateDecryptor(key))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                decryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
                case AesMode.ECB:
                    using (var _aes = CreateAes(key, ctr_iv_nonce, CipherMode.ECB, PaddingMode.None))
                    {
                        using (var decryptor = _aes.CreateDecryptor(key, _aes.IV))
                        {
                            byte[] inBuf;
                            byte[] outBuf;
                            while (count > 0)
                            {
                                inBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                outBuf = new byte[count > 0x100000 ? 0x100000 : count];
                                inStream.Read(inBuf, 0, inBuf.Length);
                                decryptor.TransformBlock(inBuf, 0, inBuf.Length, outBuf, 0);
                                outStream.Write(outBuf, 0, outBuf.Length);
                                count -= inBuf.Length;
                            }
                        }
                    }
                    break;
            }
        }

        public void SelectKeyslot(int keyslot)
        {
            if (keyslot < 0 || keyslot >= 0x40)
                throw new ArgumentException("Invalid keyslot selected. Must be in range [0, 0x40).");
            Slot = keyslot;
        }

        public void SetMode(AesMode m)
        {
            Mode = m;
        }

        public void SetCTR(byte[] ctr)
        {
            if (ctr.Length != 0x10)
                return;
            ctr.CopyTo(CTR_IV_NONCE, 0);
        }

        public void SetNandCID(byte[] cid)
        {
            if (cid.Length != 0x10)
                return;
            cid.CopyTo(_nandcid, 0);
        }

        public void AdvanceCTR(uint adv)
        {
            ulong current = (BigEndian.ToUInt32(CTR_IV_NONCE, 8));
            current <<= 32;
            current |= (BigEndian.ToUInt32(CTR_IV_NONCE, 0xC));
            ulong next = current + adv;
            BigEndian.GetBytes((uint)(next & 0xFFFFFFFF)).CopyTo(CTR_IV_NONCE, 12);
            BigEndian.GetBytes((uint)((next >> 32) & 0xFFFFFFFF)).CopyTo(CTR_IV_NONCE, 8);
            // Handle u64 overflow.
            if (next < current)
            {
                for (var ofs = 7; ofs >= 0; ofs--)
                {
                    if ((++CTR_IV_NONCE[ofs]) != 0)
                        break;
                }
            }
        }

        public void SetCTR(ulong high, ulong low)
        {
            BitConverter.GetBytes(high).Reverse().ToArray().CopyTo(CTR_IV_NONCE, 0);
            BitConverter.GetBytes(low).Reverse().ToArray().CopyTo(CTR_IV_NONCE, 8);
        }

        public void SetIV(byte[] iv)
        {
            if (iv.Length != 0x10)
                return;
            iv.CopyTo(CTR_IV_NONCE, 0);
        }

        public void SetNonce(byte[] nonce)
        {
            if (nonce.Length != 0xC)
                return;
            byte[] n = new byte[0x10];
            nonce.CopyTo(n, 0);
            n.CopyTo(CTR_IV_NONCE, 0);
        }

        public void SetMAC(byte[] mac)
        {
            if (mac.Length != 0x10)
                return;
            mac.CopyTo(MAC, 0);
        }

        public byte[] GetMAC()
        {
            return (byte[])MAC.Clone();
        }

        public void SetKeyX(int keyslot, byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(KeyXs[keyslot], 0);
            if (keyslot <= 3)
                KeyScrambler.GetDSINormalKey(KeyXs[keyslot], KeyYs[keyslot]).CopyTo(NormalKeys[keyslot], 0);
            else
                KeyScrambler.GetNormalKey(KeyXs[keyslot], KeyYs[keyslot]).CopyTo(NormalKeys[keyslot], 0);
        }

        public void SetKeyX(byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(KeyXs[Slot], 0);
            if (Slot <= 3)
                KeyScrambler.GetDSINormalKey(KeyXs[Slot], KeyYs[Slot]).CopyTo(NormalKeys[Slot], 0);
            else
                KeyScrambler.GetNormalKey(KeyXs[Slot], KeyYs[Slot]).CopyTo(NormalKeys[Slot], 0);
        }

        public void SetKeyY(int keyslot, byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(KeyYs[keyslot], 0);
            if (keyslot <= 3)
                KeyScrambler.GetDSINormalKey(KeyXs[keyslot], KeyYs[keyslot]).CopyTo(NormalKeys[keyslot], 0);
            else
                KeyScrambler.GetNormalKey(KeyXs[keyslot], KeyYs[keyslot]).CopyTo(NormalKeys[keyslot], 0);
        }

        public void SetKeyY(byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(KeyYs[Slot], 0);
            if (Slot <= 3)
                KeyScrambler.GetDSINormalKey(KeyXs[Slot], KeyYs[Slot]).CopyTo(NormalKeys[Slot], 0);
            else
                KeyScrambler.GetNormalKey(KeyXs[Slot], KeyYs[Slot]).CopyTo(NormalKeys[Slot], 0);
        }

        public void SetNormalKey(int keyslot, byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(NormalKeys[keyslot], 0);
        }
        public void SetNormalKey(byte[] key)
        {
            if (key.Length != 0x10)
                return;
            key.CopyTo(NormalKeys[Slot], 0);
        }

        public void InitializeKeyslots(byte[] boot9)
        {
            LoadKeysFromBootromFile(boot9);
        }

        public byte[] GetKeyX(uint i)
        {
            if (i >= 0x40)
                return null;
            return (byte[])(KeyXs[i].Clone());
        }
        public byte[] GetKeyY(uint i)
        {
            if (i >= 0x40)
                return null;
            return (byte[])(KeyYs[i].Clone());
        }
        public byte[] GetKey(uint i)
        {
            if (i >= 0x40)
                return null;
            return (byte[])(NormalKeys[i].Clone());
        }

        public void LoadKeysFromBootromFile(byte[] boot9)
        {
            // Will use LoadKeysFromBootrom() implementation for those who
            // don't want to manually compile with bootrom as a resource.
            byte[] hash;
            using (var sha = SHA256.Create())
            {
                hash = sha.ComputeHash(boot9);
            }
            if (hash.SequenceEqual(_boot9_hash))
            {
                IsBootRomLoaded = true;
                _boot9 = boot9;
                _boot9_prot_ofs = hash.SequenceEqual(_boot9_hash)
                    ? 0x8000
                    : 0;
            }

            var keyarea_ofs = (IsDev) ? 0x5C60 : 0x5860;
            keyarea_ofs += _boot9_prot_ofs;

            var keyX = new byte[0x10];
            var keyY = new byte[0x10];
            var normkey = new byte[0x10];

            // Skip over AESIV for consolue_unique data
            keyarea_ofs += 0x24;
            // Block 0
            keyarea_ofs += 0x74;
            // Block 1
            keyarea_ofs += 0x44;
            // Block 2
            keyarea_ofs += 0x74;
            // Block 3
            keyarea_ofs += 0x20;

            // 0x2C KeyX
            Array.Copy(boot9, keyarea_ofs, keyX, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetKeyX(0x2C + i, keyX);
            keyarea_ofs += 0x10;

            // 0x30 KeyX
            Array.Copy(boot9, keyarea_ofs, keyX, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetKeyX(0x30 + i, keyX);
            keyarea_ofs += 0x10;

            // 0x34 KeyX
            Array.Copy(boot9, keyarea_ofs, keyX, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetKeyX(0x34 + i, keyX);
            keyarea_ofs += 0x10;

            // 0x38 KeyX
            Array.Copy(boot9, keyarea_ofs, keyX, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetKeyX(0x38 + i, keyX);
            keyarea_ofs += 0x10;

            // 0x3C-0x3F KeyX
            for (var i = 0; i < 4; i++)
            {
                Array.Copy(boot9, keyarea_ofs, keyX, 0, 0x10);
                SetKeyX(0x3C + i, keyX);
                keyarea_ofs += 0x10;
            }

            // 0x4-0xB KeyY
            for (var i = 0; i < 8; i++)
            {
                Array.Copy(boot9, keyarea_ofs, keyY, 0, 0x10);
                SetKeyY(0x4 + i, keyY);
                keyarea_ofs += 0x10;
            }

            // 0xC Normkey
            Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetNormalKey(0xC + i, normkey);
            keyarea_ofs += 0x10;

            // 0x10 Normkey
            Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetNormalKey(0x10 + i, normkey);
            keyarea_ofs += 0x10;

            // 0x14-0x17 normkey
            for (var i = 0; i < 4; i++)
            {
                Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
                SetNormalKey(0x14 + i, normkey);
                keyarea_ofs += 0x10;
            }

            // 0x18 normkey
            Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetNormalKey(0x18 + i, normkey);
            keyarea_ofs += 0x10;

            // 0x1C Normkey
            Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetNormalKey(0x1C + i, normkey);
            keyarea_ofs += 0x10;

            // 0x20 Normkey
            Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetNormalKey(0x20 + i, normkey);
            keyarea_ofs += 0x10;

            // 0x24 Normkey
            Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetNormalKey(0x24 + i, normkey);
            // No increase

            // 0x28-0x2C normkey
            for (var i = 0; i < 4; i++)
            {
                Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
                SetNormalKey(0x28 + i, normkey);
                keyarea_ofs += 0x10;
            }

            // 0x2C Normkey
            Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetNormalKey(0x2C + i, normkey);
            keyarea_ofs += 0x10;

            // 0x30 Normkey
            Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetNormalKey(0x30 + i, normkey);
            keyarea_ofs += 0x10;

            // 0x34 Normkey
            Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetNormalKey(0x34 + i, normkey);
            keyarea_ofs += 0x10;

            // 0x38 Normkey
            Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
            for (var i = 0; i < 4; i++)
                SetNormalKey(0x38 + i, normkey);

            // 0x3C-0x3F normkeys
            for (var i = 0; i < 4; i++)
            {
                Array.Copy(boot9, keyarea_ofs, normkey, 0, 0x10);
                SetNormalKey(0x3C + i, normkey);
                keyarea_ofs += 0x10;
            }

        }

        public byte[] DecryptBOSS(byte[] boss)
        {
            var ctr = new byte[0x10];
            Array.Copy(boss, 0x1C, ctr, 0x0, 0xC);
            ctr[0xF] = 0x1;

            SelectKeyslot(0x38);
            SetMode(AesMode.CTR);
            SetCTR(ctr);

            var encdata = new byte[boss.Length - 0x28];
            Array.Copy(boss, 0x28, encdata, 0, encdata.Length);
            var decdata = Decrypt(encdata);

            var decboss = new byte[boss.Length];
            Array.Copy(boss, decboss, 0x28);
            decdata.CopyTo(decboss, 0x28);

            return decboss;
        }

    }
    public static class StringExtentions
    {
        public static byte[] ToByteArray(this string toTransform)
        {
            return Enumerable
                .Range(0, toTransform.Length / 2)
                .Select(i => Convert.ToByte(toTransform.Substring(i * 2, 2), 16))
                .ToArray();
        }
    }

    public static class ByteArrayExtensions
    {
        public static string ToHexString(this byte[] ba)
        {
            StringBuilder hex = new StringBuilder(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:X2}", b);
            return hex.ToString();
        }
    }
}
