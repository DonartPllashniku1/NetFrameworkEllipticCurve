using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace LakoretConsole
{

    class Personi1
    {
        public static byte[] personi1PublicKey;

        public static void Main(string[] args)
        {
            using (ECDiffieHellmanCng personi1 = new ECDiffieHellmanCng())
            {

                personi1.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                personi1.HashAlgorithm = CngAlgorithm.Sha256;
                personi1PublicKey = personi1.PublicKey.ToByteArray();
                Personi2 personi2 = new Personi2();
                CngKey k = CngKey.Import(personi2.personi2PublicKey, CngKeyBlobFormat.EccPublicBlob);
                byte[] personi1Key = personi1.DeriveKeyMaterial(CngKey.Import(personi2.personi2PublicKey, CngKeyBlobFormat.EccPublicBlob));
                byte[] encryptedMessage = null;
                byte[] iv = null;
                var msg = "Secret message from first person!";
                Send(personi1Key, msg, out encryptedMessage, out iv);
                Console.WriteLine(msg + " -Message to be Encrypted");
                personi2.Receive(encryptedMessage, iv);
            }

        }

        private static void Send(byte[] key, string secretMessage, out byte[] encryptedMessage, out byte[] iv)
        {
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = key;
                iv = aes.IV;

                // Encrypt message 
                using (MemoryStream ciphertext = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ciphertext, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    byte[] plaintextMessage = Encoding.UTF8.GetBytes(secretMessage);
                    cs.Write(plaintextMessage, 0, plaintextMessage.Length);
                    cs.Close();
                    encryptedMessage = ciphertext.ToArray();
                }
            }
        }

    }
    public class Personi2
    {
        public byte[] personi2PublicKey;
        private byte[] personi2Key;
        public Personi2()
        {
            using (ECDiffieHellmanCng personi2 = new ECDiffieHellmanCng())
            {

                personi2.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
                personi2.HashAlgorithm = CngAlgorithm.Sha256;
                personi2PublicKey = personi2.PublicKey.ToByteArray();
                personi2Key = personi2.DeriveKeyMaterial(CngKey.Import(Personi1.personi1PublicKey, CngKeyBlobFormat.EccPublicBlob));

            }
        }

        public void Receive(byte[] encryptedMessage, byte[] iv)
        {
            Console.WriteLine(" -Decrypted Message");
            using (Aes aes = new AesCryptoServiceProvider())
            {
                aes.Key = personi2Key;
                aes.IV = iv;
                // Decrypt message 
                using (MemoryStream plaintext = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(plaintext, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                        cs.Close();
                        string message = Encoding.UTF8.GetString(plaintext.ToArray());
                        Console.WriteLine(message + " -Decrypted Message");
                        var res = message;

                    }
                }
            }
        }

    }
}

