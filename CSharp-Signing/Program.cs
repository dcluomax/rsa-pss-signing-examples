using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace signingtest
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] signature;

            byte[] rawData = File.ReadAllBytes("selfsign.pfx");
            X509Certificate2 cert = new X509Certificate2(rawData, "", X509KeyStorageFlags.Exportable);

            byte[] hash;

            using (var sha256 = new SHA256CryptoServiceProvider())
            {
                var msg = "My secret message.222";
                hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(msg));
                using (RSACng rsa = cert.GetRSAPrivateKey() as RSACng)
                {
                    // Sign the hash
                    signature = rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                    rsa.Clear();
                }
            }
            Console.WriteLine("====signature===");
            Console.WriteLine(Convert.ToBase64String(signature), Base64FormattingOptions.InsertLineBreaks);
            var base64Cert = Convert.ToBase64String(cert.Export(X509ContentType.Cert), Base64FormattingOptions.InsertLineBreaks);
            Console.WriteLine("====public cert===");
            Console.WriteLine(base64Cert);
            Console.WriteLine("====public key===");
            base64Cert = Convert.ToBase64String(cert.GetPublicKey(), Base64FormattingOptions.InsertLineBreaks);
            Console.WriteLine(base64Cert);
            Console.WriteLine("====private key===");
            // !! not PEM private key
            base64Cert = Convert.ToBase64String(cert.Export(X509ContentType.Pkcs12), Base64FormattingOptions.InsertLineBreaks);
            Console.WriteLine(base64Cert);
            RSACng rsapk = cert.GetRSAPublicKey() as RSACng;
            bool checkSig = rsapk.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            Console.WriteLine("=======");
            Console.WriteLine(checkSig);
        }


    }
}
