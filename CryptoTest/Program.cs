using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace Client
{
    class Program
    {
        static void Main(string[] args)
        {
            Crypto alice = new Crypto();
            Crypto bob = new Crypto();

            alice.GenPrivateKey(bob.GetPublicKey());
            bob.GenPrivateKey(alice.GetPublicKey());

            byte[] message = Encoding.Unicode.GetBytes("This is a test:");
            byte[] encryptedMessage;
            byte[] iv;

            encryptedMessage = alice.Encrypt(message, out iv);

            message = null;

            message = bob.Decrypt(encryptedMessage, iv);

            Console.WriteLine(Encoding.Unicode.GetString(message));

            int amount = 1000;

            for (int i = 0; i < amount; i++)
            {
                message = null;
                encryptedMessage = null;

                message = Encoding.Unicode.GetBytes("Hello world! " + (i + 1));

                encryptedMessage = alice.Encrypt(message, out iv);

                message = null;

                message = bob.Decrypt(encryptedMessage, iv);

                Console.WriteLine(Encoding.Unicode.GetString(message));
            }

            Console.WriteLine("Done encrypting and decrypting byte array " + amount + " times!");

            Thread.Sleep(3000);
        }
    }
}
public class Crypto
{
    private bool ready = false;
    private byte[] publicKey = null;
    private byte[] privateKey = null;
    private ECDiffieHellmanCng keyPair = null;

    public Crypto()
    {
        keyPair = new ECDiffieHellmanCng
        {
            KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
            HashAlgorithm = CngAlgorithm.Sha256
        };
        publicKey = keyPair.PublicKey.ToByteArray();
    }

    public void GenPrivateKey(byte[] key)
    {
        privateKey = keyPair.DeriveKeyMaterial(CngKey.Import(key, CngKeyBlobFormat.EccPublicBlob));
        ready = true;
    }

    public byte[] GetPublicKey()
    {
        return publicKey;
    }
    public byte[] Encrypt(byte[] unencryptedData, out byte[] iv)
    {
        if (!ready || unencryptedData == null)
        {
            iv = null;
            return null;
        }

        using (Aes aes = new AesCryptoServiceProvider())
        {
            aes.Key = privateKey;
            iv = aes.IV;

            // Encrypt the data
            using (MemoryStream encryptedData = new MemoryStream())
            using (CryptoStream stream = new CryptoStream(encryptedData, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                try
                {
                    stream.Write(unencryptedData, 0, unencryptedData.Length);
                    stream.Close();
                }
                catch (System.Security.Cryptography.CryptographicException)
                {
                    return null;
                }

                return encryptedData.ToArray();
            }
        }
    }
    public byte[] Decrypt(byte[] encryptedData, byte[] iv)
    {
        if (!ready || encryptedData == null || iv == null)
        {
            return null;
        }

        using (Aes aes = new AesCryptoServiceProvider())
        {
            aes.Key = privateKey;
            aes.IV = iv;

            // Decrypt the data
            using (MemoryStream decryptedData = new MemoryStream())
            {
                using (CryptoStream stream = new CryptoStream(decryptedData, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    try
                    {
                        stream.Write(encryptedData, 0, encryptedData.Length);
                        stream.Close();
                    }
                    catch (System.Security.Cryptography.CryptographicException)
                    {
                        return null;
                    }

                    return decryptedData.ToArray();
                }
            }
        }
    }
}