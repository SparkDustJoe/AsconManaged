using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using AsconManaged;
namespace AsconManagedTester
{
    public class Program
    {
        static void Main(string[] args)
        {
            // make sure we have all 5 KATS files (ciphertext/message digest result values only, one per line, "#,HEX")
            string[] lines80pq = File.ReadAllLines(@".\LWC_AEAD_KAT_160_128_CT_ONLY.txt");
            string[] lines128 = File.ReadAllLines(@".\LWC_AEAD_KAT_128_128_CT_ONLY.txt");
            string[] lines128a = File.ReadAllLines(@".\LWC_AEAD_KAT_128a_128a_CT_ONLY.txt");
            string[] linesHash = File.ReadAllLines(@".\LWC_HASH_KAT_256_MD_ONLY.txt");
            string[] linesXof = File.ReadAllLines(@".\LWC_XOF_KAT_256_MD_ONLY.txt");

            byte[] source = HexString2ByteArray("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"); // 256 bits
            byte[] Key = HexString2ByteArray("000102030405060708090A0B0C0D0E0F"); // 128 bits
            byte[] Key80pq = HexString2ByteArray("000102030405060708090A0B0C0D0E0F10111213"); // 160 bits
            byte[] Nonce = (byte[])Key.Clone();
            int PASSENC = 0;
            int PASSVER = 0;
            int PASSDEC = 0;
            int FAILENC = 0;
            int FAILVER = 0;
            int FAILDEC = 0;
            int TESTSTOTAL = 0;
            int TOTALFAILS = 0;
            Write("All Tests for Ascon80pq =======================================================================", MessageType.Informational);
            foreach (string line in lines80pq)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                TESTSTOTAL++;
                string[] columns = line.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                int testNum = int.Parse(columns[0]);
                Write($"Test #{testNum:0000} -- ", MessageType.Normal, false);
                testNum--; // in the file, this is 1 indexed, we need it 0 indexed
                byte[] PT = new byte[(int)(testNum / 33)];
                byte[] AD = new byte[testNum % 33];
                Buffer.BlockCopy(source, 0, PT, 0, PT.Length);
                Buffer.BlockCopy(source, 0, AD, 0, AD.Length);
                Write($"LenPT={PT.Length:00}, LenAD={AD.Length:00}, ", MessageType.Normal, false);
                string ct_hex = columns[1];
                byte[] ct = HexString2ByteArray(ct_hex);
                byte[] result = AsconManaged.ASCON_80pq.Encrypt(Nonce, Key80pq, AD, PT);
                if (CompareArrays(ct, result))
                {
                    Write("Encryption PASS, ", MessageType.OK, false);
                    PASSENC++;
                }
                else
                {
                    FAILENC++;
                    Write("*Encrypt FAIL!!, ", MessageType.Error, false);
                }
                byte[] returnResult = ASCON_80pq.DecryptVerify(Nonce, Key80pq, AD, result);
                if (returnResult == null)
                {
                    FAILVER++;
                    FAILDEC++;
                    Write("*Verificaiton FAIL!! (null return)", MessageType.Error);
                }
                else
                {
#if !DEBUG
                    Write("Verificaiton PASS (non-null return), ", MessageType.OK, false);
                    PASSVER++;
#else
                    Write("--Verification Skipped--, ", MessageType.Warning, false);
#endif //!DEBUG
                    if (CompareArrays(PT, returnResult))
                    {
                        Write("Decryption PASS", MessageType.OK);
                        PASSDEC++;
                    }
                    else
                    {
                        FAILDEC++;
                        Write("*Decryption FAIL!!", MessageType.Error);
                    }
                }
            }
            Write($"===========Done. Stats (Pass/Fail):     (Total Tests = {TESTSTOTAL})", MessageType.Informational);
            Write($"Encryption: {PASSENC}/{FAILENC}", MessageType.Informational);
            Write($"Verification: {PASSVER}/{FAILVER}", MessageType.Informational);
            Write($"Decryption: {PASSDEC}/{FAILDEC}", MessageType.Informational);
            TOTALFAILS += FAILDEC + FAILENC + FAILVER;
            Write("All Tests for Ascon128 =======================================================================", MessageType.Informational);
            PASSENC = 0;
            PASSVER = 0;
            PASSDEC = 0;
            FAILENC = 0;
            FAILVER = 0;
            FAILDEC = 0;
            TESTSTOTAL = 0;
            foreach (string line in lines128)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                TESTSTOTAL++;
                string[] columns = line.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                int testNum = int.Parse(columns[0]);
                Write($"Test #{testNum:0000} -- ", MessageType.Normal, false);
                testNum--; // in the file, this is 1 indexed, we need it 0 indexed
                byte[] PT = new byte[(int)(testNum / 33)];
                byte[] AD = new byte[testNum % 33];
                Buffer.BlockCopy(source, 0, PT, 0, PT.Length);
                Buffer.BlockCopy(source, 0, AD, 0, AD.Length);
                Write($"LenPT={PT.Length:00}, LenAD={AD.Length:00}, ", MessageType.Normal, false);
                string ct_hex = columns[1];
                byte[] ct = HexString2ByteArray(ct_hex);
                byte[] result = AsconManaged.ASCON_128.Encrypt(Nonce, Key, AD, PT);
                if (CompareArrays(ct, result))
                {
                    Write("Encryption PASS, ", MessageType.OK, false);
                    PASSENC++;
                }
                else
                {
                    FAILENC++;
                    Write("*Encrypt FAIL!!, ", MessageType.Error, false);
                }
                byte[] returnResult = ASCON_128.DecryptVerify(Nonce, Key, AD, result);
                if (returnResult == null)
                {
                    FAILVER++;
                    FAILDEC++;
                    Write("*Verificaiton FAIL!! (null return)", MessageType.Error);
                }
                else
                {
#if !DEBUG
                    Write("Verificaiton PASS (non-null return), ", MessageType.OK, false);
                    PASSVER++;
#else
                    Write("--Verification Skipped--, ", MessageType.Warning, false);
#endif //!DEBUG
                    if (CompareArrays(PT, returnResult))
                    {
                        Write("Decryption PASS", MessageType.OK);
                        PASSDEC++;
                    }
                    else
                    {
                        FAILDEC++;
                        Write("*Decryption FAIL!!", MessageType.Error);
                    }
                }
            }
            Write($"===========Done. Stats (Pass/Fail):     (Total Tests = {TESTSTOTAL})", MessageType.Informational);
            Write($"Encryption: {PASSENC}/{FAILENC}", MessageType.Informational);
            Write($"Verification: {PASSVER}/{FAILVER}", MessageType.Informational);
            Write($"Decryption: {PASSDEC}/{FAILDEC}", MessageType.Informational);
            TOTALFAILS += FAILDEC + FAILENC + FAILVER;
            Write("All Tests for Ascon128a ===============================================================", MessageType.Informational);
            PASSENC = 0;
            PASSVER = 0;
            PASSDEC = 0;
            FAILENC = 0;
            FAILVER = 0;
            FAILDEC = 0;
            TESTSTOTAL = 0;
            foreach (string line in lines128a)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                TESTSTOTAL++;
                string[] columns = line.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                int testNum = int.Parse(columns[0]);
                Write($"Test #{testNum:0000} -- ", MessageType.Normal, false);
                testNum--; // in the file, this is 1 indexed, we need it 0 indexed
                byte[] PT = new byte[(int)(testNum / 33)];
                byte[] AD = new byte[testNum % 33];
                Buffer.BlockCopy(source, 0, PT, 0, PT.Length);
                Buffer.BlockCopy(source, 0, AD, 0, AD.Length);
                Write($"LenPT={PT.Length:00}, LenAD={AD.Length:00}, ", MessageType.Normal, false);
                string ct_hex = columns[1];
                byte[] ct = HexString2ByteArray(ct_hex);
                byte[] result = AsconManaged.ASCON_128a.Encrypt(Nonce, Key, AD, PT);
                if (CompareArrays(ct, result))
                {
                    Write("Encryption PASS, ", MessageType.OK, false);
                    PASSENC++;
                }
                else
                {
                    FAILENC++;
                    Write("*Encrypt FAIL!!, ", MessageType.Error, false);
                }
                byte[] returnResult = ASCON_128a.DecryptVerify(Nonce, Key, AD, result);
                if (returnResult == null)
                {
                    FAILVER++;
                    FAILDEC++;
                    Write("*Verificaiton FAIL!! (null return) ", MessageType.Error);
                }
                else
                {
#if !DEBUG
                    Write("Verificaiton PASS (non-null return), ", MessageType.OK, false);
                    PASSVER++;
#else
                    Write("--Verification Skipped--, ", MessageType.Warning, false);
#endif //!DEBUG
                    if (CompareArrays(PT, returnResult))
                    {
                        Write("Decryption PASS", MessageType.OK);
                        PASSDEC++;
                    }
                    else
                    {
                        FAILDEC++;
                        Write("*Decryption FAIL!!", MessageType.Error);
                    }
                }
            }
            Write($"===========Done. Stats (Pass/Fail):     (Total Tests = {TESTSTOTAL})", MessageType.Informational);
            Write($"Encryption: {PASSENC}/{FAILENC}", MessageType.Informational);
            Write($"Verification: {PASSVER}/{FAILVER}", MessageType.Informational);
            Write($"Decryption: {PASSDEC}/{FAILDEC}", MessageType.Informational);
            TOTALFAILS += FAILDEC + FAILENC + FAILVER;
            Write("All Tests for Ascon Hash ===============================================================", MessageType.Informational);
            source = new byte[1024];
            for (short i = 0; i < 1024; i++) source[i] = (byte)(i & 0x00FF);
            PASSENC = 0;
            FAILENC = 0;
            TESTSTOTAL = 0;
            foreach (string line in linesHash)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                TESTSTOTAL++;
                string[] columns = line.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                int testNum = int.Parse(columns[0]);
                Write($"Test #{testNum:0000} -- ", MessageType.Normal, false);
                testNum--; // in the file, this is 1 indexed, we need it 0 indexed
                byte[] MSG = new byte[(int)(testNum)];
                string digest_hex = columns[1];
                byte[] digest = HexString2ByteArray(digest_hex);
                Buffer.BlockCopy(source, 0, MSG, 0, MSG.Length);
                Write($"Len={MSG.Length:0000}, ", MessageType.Normal, false);
                byte[] result = AsconManaged.ASCON_Hash.ComputeHash(MSG);
                if (CompareArrays(result, digest))
                {
                    Write("HASH PASS", MessageType.OK);
                    PASSENC++;
                }
                else
                {
                    FAILENC++;
                    Write("*HASH FAIL!! ", MessageType.Error);
                }
            }
            Write($"===========Done. Stats (Pass/Fail):     (Total Tests = {TESTSTOTAL})", MessageType.Informational);
            Write($"Hash: {PASSENC}/{FAILENC}", MessageType.Informational);
            TOTALFAILS += FAILENC;
            Write("All Tests for Ascon Xof ===============================================================", MessageType.Informational);
            source = new byte[1024];
            for (short i = 0; i < 1024; i++) source[i] = (byte)(i & 0x00FF);
            PASSENC = 0;
            FAILENC = 0;
            TESTSTOTAL = 0;
            foreach (string line in linesXof)
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                TESTSTOTAL++;
                string[] columns = line.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                int testNum = int.Parse(columns[0]);
                Write($"Test #{testNum:0000} -- ", MessageType.Normal, false);
                testNum--; // in the file, this is 1 indexed, we need it 0 indexed
                byte[] MSG = new byte[(int)(testNum)];
                string digest_hex = columns[1];
                byte[] digest = HexString2ByteArray(digest_hex);
                Buffer.BlockCopy(source, 0, MSG, 0, MSG.Length);
                Write($"Len={MSG.Length:0000}, ", MessageType.Normal, false);
                byte[] result = AsconManaged.ASCON_Xof.ComputeHash(MSG);
                if (CompareArrays(result, digest))
                {
                    Write("HASH PASS", MessageType.OK);
                    PASSENC++;
                }
                else
                {
                    FAILENC++;
                    Write("*HASH FAIL!! ", MessageType.Error);
                }
            }
            Write($"===========Done. Stats (Pass/Fail):     (Total Tests = {TESTSTOTAL})", MessageType.Informational);
            Write($"Hash: {PASSENC}/{FAILENC}", MessageType.Informational);
            TOTALFAILS += FAILENC;
            Console.WriteLine("****************************************************************************************");
            if (TOTALFAILS == 0)
                Write($"TOTAL FAILS = {TOTALFAILS}", MessageType.OK);
            else
                Write($"TOTAL FAILS = {TOTALFAILS}", MessageType.Error);

            while (Console.KeyAvailable) { Console.ReadKey(true); }
            Write("Press ENTER to leave application...", MessageType.Informational);
            Console.ReadLine();
        }

        static byte[] HexString2ByteArray(string s)
        {
            if (s == null) return null;
            if (string.IsNullOrWhiteSpace(s)) return new byte[0];
            byte[] result = new byte[s.Length / 2];
            for (int i = 0; i < s.Length; i += 2)
            {
                result[i / 2] = byte.Parse(s.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
            }
            return result;
        }

        static bool CompareArrays(byte[] a, byte[] b)
        {
            if (a == null && b != null && b.Length == 0)
                return true;
            if (b == null && a != null && a.Length == 0)
                return true;
            if (a.Length != b.Length)
                return false;
            int result = 0;
            for (int i = 0; i < a.Length; i++) result |= a[i] ^ b[i];
            return result == 0;
        }

        public enum MessageType : byte
        {
            Normal = 0,
            OK,
            Informational,
            Warning,
            Error
        };

        static void Write(string message, MessageType type, bool endOfLine = true)
        {
            ConsoleColor FGB = Console.ForegroundColor;
            ConsoleColor BGB = Console.BackgroundColor;
            switch(type)
            {
                case MessageType.Informational:
                    Console.ForegroundColor = ConsoleColor.Cyan;
                    break;
                case MessageType.OK:
                    Console.ForegroundColor = ConsoleColor.Green;
                    break;
                case MessageType.Warning:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    break;
                case MessageType.Error:
                    Console.ForegroundColor = ConsoleColor.Red;
                    break;
                case MessageType.Normal:
                default:
                    Console.ForegroundColor = ConsoleColor.White;
                    break;
            }
            if (endOfLine)
                Console.WriteLine(message);
            else
                Console.Write(message); 
            Console.ForegroundColor = FGB;
            Console.BackgroundColor = BGB;
        }
    }
}
