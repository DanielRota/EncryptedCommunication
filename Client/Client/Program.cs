using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Client;

namespace ClientAsymmetricCommunication
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            Console.WriteLine("############################################################################");
            Console.WriteLine("###################                                    #####################");
            Console.WriteLine("###############      ClientSide RSA/AES Communication      #################");
            Console.WriteLine("###################                                    #####################");
            Console.WriteLine("############################################################################\n");

            Client? client = new Client();

            while (true)
            {
                Console.Write("Name: ");
                string? name = Console.ReadLine();

                if (!string.IsNullOrEmpty(name))
                {
                    client.Name = name;
                    break;
                }

                Console.WriteLine("Name is null");
            }

            try
            {
                client.ConnectEndPoint("localhost", 3000);
                client.Running = true;
                client.WriteThread.Start();

                while (client.Running)
                {
                    byte[]? buffer = new byte[2048];
                    int bytes = client.Socket.Receive(buffer, SocketFlags.None);
                    int nullIndex = Array.FindIndex(buffer, b => b == 0x00);

                    if (nullIndex > -1)
                    {
                        byte[]? newBuffer = new byte[nullIndex];
                        Array.Copy(buffer, newBuffer, nullIndex);
                        buffer = newBuffer;
                    }

                    string? json = Encoding.UTF8.GetString(buffer);
                    MessageFormat? format = System.Text.Json.JsonSerializer.Deserialize<MessageFormat>(json);

                    if (format == null)
                    {
                        Console.WriteLine("Message is null");
                        break;
                    }

                    if (bytes > 0)
                    {
                        switch (format.Flag)
                        {
                            case MessageFormat.PackageType.Username:
                                {
                                    client.Keys.TryAdd(format.Sender, format.RsaPublicKey);
                                    break;
                                }
                            case MessageFormat.PackageType.Message:
                                {
                                    byte[]? decryptedMessage = new byte[64];
                                    byte[]? aesDecryptedKey = client.Decryptor.DoFinal(format.EncryptyedAesKey);

                                    using (var aes = Aes.Create())
                                    {
                                        aes.KeySize = 256;
                                        aes.Padding = PaddingMode.Zeros;

                                        aes.IV = format.AesInitializationVector;
                                        aes.Key = aesDecryptedKey;

                                        decryptedMessage = aes.DecryptCbc(format.EncryptedMessage, format.AesInitializationVector, PaddingMode.Zeros);
                                    }

                                    Console.WriteLine("\n##### {0}: {1}", format.Sender, Encoding.ASCII.GetString(decryptedMessage, 0, decryptedMessage.Length));
                                    break;
                                }
                            case MessageFormat.PackageType.Update:
                                {
                                    format.UserKeys.ForEach(c => client.Keys.Add(c.User, c.Key));
                                    break;
                                }
                            case MessageFormat.PackageType.Join:
                                {
                                    client.Keys.Add(format.Sender, format.RsaPublicKey);
                                    break;
                                }
                        }
                    }

                    format.Dispose();
                }
            }
            catch (SocketException se)
            {
                Console.WriteLine("\nSocketException: {0}", se.ToString());
                client.Running = false;
            }
            catch (CryptographicException ce)
            {
                Console.WriteLine("\nCryptographicException: {0}", ce.ToString());
                client.Running = false;
            }
            catch (Exception e)
            {
                Console.WriteLine("\nException: {0}", e.ToString());
                client.Running = false;
            }

            while (true) { }
        }
    }
}
