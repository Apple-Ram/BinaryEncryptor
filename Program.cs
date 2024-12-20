using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BinaryEncryptor
{
    class Program
    {
        private static readonly int KeySize = 32;
        private static readonly int IvSize = 16;
        private static readonly int Iterations = 100000;

        static void Main(string[] args)
        {
            while (true)
            {
                Console.WriteLine("Binary Encryptor");
                Console.WriteLine("1. Encrypt a binary file");
                Console.WriteLine("2. Decrypt an encrypted text file");
                Console.WriteLine("3. Exit");
                Console.Write("Choose an option (1-3): ");

                string choice = Console.ReadLine();
                Console.WriteLine();

                switch (choice)
                {
                    case "1":
                        EncryptFile();
                        break;
                    case "2":
                        DecryptFile();
                        break;
                    case "3":
                        return;
                    default:
                        Console.WriteLine("Type 1, or 2.\n");
                        break;
                }
            }
        }
        static void EncryptFile()
        {
            Console.Write("Enter the path of the file to encrypt: ");
            string filePath = Console.ReadLine();

            if (!File.Exists(filePath))
            {
                Console.WriteLine("File does not exist.\n");
                return;
            }

            Console.Write("Password for encrypting: ");
            string password = ReadPassword();

            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                byte[] encryptedBytes = EncryptBytes(fileBytes, password);

                string base64String = Convert.ToBase64String(encryptedBytes);
                string txtPath = Path.ChangeExtension(filePath, ".txt");

                File.WriteAllText(txtPath, base64String);
                Console.WriteLine($"Successfully encrypted! Saved to: {txtPath}\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error during encryption: {ex.Message}\n");
            }
        }

        static void DecryptFile()
        {
            Console.Write("Enter the path of the encrypted text file to decrypt: ");
            string txtPath = Console.ReadLine();

            if (!File.Exists(txtPath))
            {
                Console.WriteLine("File does not exist.\n");
                return;
            }

            Console.Write("Password for decrypting: ");
            string password = ReadPassword();

            try
            {
                string base64String = File.ReadAllText(txtPath).Trim();

                if (string.IsNullOrEmpty(base64String))
                {
                    Console.WriteLine("Text file is empty.\n");
                    return;
                }

                byte[] encryptedBytes = Convert.FromBase64String(base64String);
                byte[] decryptedBytes = DecryptBytes(encryptedBytes, password);

                string originalExtension = Path.GetExtension(Path.ChangeExtension(txtPath, ""));
                string decryptedFilePath = Path.ChangeExtension(txtPath, originalExtension);

                File.WriteAllBytes(decryptedFilePath, decryptedBytes);
                Console.WriteLine($"Successfully decrypted! Saved to: {decryptedFilePath}\n");
            }
            catch (FormatException)
            {
                Console.WriteLine("Invalid data in text file.\n");
            }
            catch (CryptographicException)
            {
                Console.WriteLine("Wrong Password !\n");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error : {ex.Message}\n");
            }
        }
        static byte[] EncryptBytes(byte[] data, string password)
        {
            using (Aes aes = Aes.Create())
            {
                using (var keyDerivation = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes("SaltySalt"), Iterations))
                {
                    aes.Key = keyDerivation.GetBytes(KeySize);
                    aes.IV = keyDerivation.GetBytes(IvSize);
                }

                using (var ms = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(data, 0, data.Length);
                        cryptoStream.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }
        static byte[] DecryptBytes(byte[] encryptedData, string password)
        {
            using (Aes aes = Aes.Create())
            {
                using (var keyDerivation = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes("SaltySalt"), Iterations))
                {
                    aes.Key = keyDerivation.GetBytes(KeySize);
                    aes.IV = keyDerivation.GetBytes(IvSize);
                }

                using (var ms = new MemoryStream())
                {
                    using (var cryptoStream = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(encryptedData, 0, encryptedData.Length);
                        cryptoStream.FlushFinalBlock();
                        return ms.ToArray();
                    }
                }
            }
        }
        static string ReadPassword()
        {
            StringBuilder password = new StringBuilder();
            ConsoleKeyInfo keyInfo;

            do
            {
                keyInfo = Console.ReadKey(intercept: true);
                if (keyInfo.Key == ConsoleKey.Backspace && password.Length > 0)
                {
                    Console.Write("\b \b");
                    password.Length--;
                }
                else if (!char.IsControl(keyInfo.KeyChar))
                {
                    Console.Write("*");
                    password.Append(keyInfo.KeyChar);
                }
            } while (keyInfo.Key != ConsoleKey.Enter);
            Console.WriteLine();

            return password.ToString();
        }
    }
}
