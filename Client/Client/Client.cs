using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Client;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace ClientAsymmetricCommunication
{
    public class Client
    {
        public Socket Socket { get; set; }
        public Thread WriteThread { get; set; }
        public IBufferedCipher Encryptor { get; set; }
        public IBufferedCipher Decryptor { get; set; }
        public RsaKeyParameters PublicKey { get; set; }
        public RsaPrivateCrtKeyParameters PrivateKey { get; set; }
        public Dictionary<string, byte[]> Keys { get; set; }
        public string Name { get; set; } = string.Empty;
        public bool Running { get; set; } = false;

        public Client()
        {
            this.Socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            this.WriteThread = new Thread(() => WriteBuffer());
            this.Encryptor = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            this.Decryptor = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
            this.GenerateRsaKeyPair();
            this.Encryptor.Init(true, this.PublicKey);
            this.Decryptor.Init(false, this.PrivateKey);
            this.Keys = new Dictionary<string, byte[]>();
        }

        public void ConnectEndPoint(string host, int port)
        {
            IPAddress? address = Dns.GetHostEntry(host).AddressList[0];
            IPEndPoint? endPoint = new IPEndPoint(address, port);
            this.Socket.Connect(endPoint);

            var format = new SocketMessageFormat
            {
                Flag = SocketMessageFormat.SocketMessageFlag.Username,
                Sender = this.Name,
                RsaPublicKey = this.GetPublicKeyBytes(this.PublicKey)
            };

            string? json = System.Text.Json.JsonSerializer.Serialize(format);
            byte[]? buffer = Encoding.ASCII.GetBytes(json);
            this.Socket.Send(buffer);
        }

        public void WriteBuffer()
        {
            while (this.Running)
            {
                string? receiver = "";
                string? message = "";

                byte[]? aesIv = new byte[16];
                byte[]? aesKey = new byte[16];
                byte[]? aesEncryptedKey = new byte[32];
                byte[]? encryptedMessage = new byte[32];

                while (this.Running)
                {
                    Console.Write("Receiver: ");
                    receiver = Console.ReadLine();
                    if (!string.IsNullOrEmpty(receiver) && this.Keys.ContainsKey(receiver)) break;
                    Console.WriteLine("User not found");
                }

                if (receiver == null)
                {
                    Console.WriteLine("Receiver is null");
                    break;
                }

                while (this.Running)
                {
                    Console.Write("Message: ");
                    message = Console.ReadLine();
                    if (!string.IsNullOrEmpty(message)) break;
                    Console.WriteLine("Message can't be null");
                }

                if (message == null)
                {
                    Console.WriteLine("Message is null");
                    break;
                }

                byte[]? publicKeyReceiverBytes = this.Keys[receiver];
                RsaKeyParameters? publicKeyReceiver = this.GetRsaKeyParameters(publicKeyReceiverBytes);

                if (publicKeyReceiver == null)
                {
                    Console.WriteLine("User not found");
                    break;
                }

                using (var aes = Aes.Create())
                {
                    IBufferedCipher rsa = CipherUtilities.GetCipher("RSA/ECB/PKCS1Padding");
                    rsa.Init(true, publicKeyReceiver);

                    aes.KeySize = 256;
                    aes.Padding = PaddingMode.Zeros;

                    aes.GenerateIV();
                    aes.GenerateKey();

                    Array.Copy(aes.IV, aesIv, aesIv.Length);
                    Array.Copy(aes.Key, aesKey, aesKey.Length);

                    aesEncryptedKey = rsa.DoFinal(aes.Key);
                    encryptedMessage = aes.EncryptCbc(Encoding.ASCII.GetBytes(message), aes.IV, PaddingMode.Zeros);
                }

                var format = new SocketMessageFormat
                {
                    Flag = SocketMessageFormat.SocketMessageFlag.Message,
                    Receiver = receiver,
                    Sender = this.Name,
                    EncryptyedAesKey = aesEncryptedKey,
                    EncryptedMessage = encryptedMessage,
                    AesInitializationVector = aesIv
                };

                string? json = System.Text.Json.JsonSerializer.Serialize(format);
                byte[]? buffer = Encoding.ASCII.GetBytes(json);
                this.Socket.SendAsync((ArraySegment<byte>)buffer, SocketFlags.None);
                Console.WriteLine($"##### {this.Name} (You): {message}");
                format.Dispose();
            }
        }

        public void GenerateRsaKeyPair()
        {
            var keyPairGenerator = new RsaKeyPairGenerator();
            keyPairGenerator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
            AsymmetricCipherKeyPair keyPair = keyPairGenerator.GenerateKeyPair();

            RsaKeyParameters publicKey = (RsaKeyParameters)keyPair.Public;
            RsaPrivateCrtKeyParameters privateKey = (RsaPrivateCrtKeyParameters)keyPair.Private;

            this.PublicKey = publicKey;
            this.PrivateKey = privateKey;
        }

        public byte[] GetPublicKeyBytes(AsymmetricKeyParameter publicKey)
        {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
            return publicKeyInfo.GetEncoded();
        }

        public byte[] GetPrivateKeyBytes(AsymmetricKeyParameter privateKey)
        {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
            return privateKeyInfo.GetEncoded();
        }

        public RsaKeyParameters GetRsaKeyParameters(byte[] publicKeyBytes)
        {
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfo.GetInstance(publicKeyBytes);
            return (RsaKeyParameters)PublicKeyFactory.CreateKey(publicKeyInfo);
        }

        public RsaPrivateCrtKeyParameters GetRsaPrivateCrtKeyParameters(byte[] privateKeyBytes)
        {
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfo.GetInstance(privateKeyBytes);
            return (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(privateKeyInfo);
        }
    }
}
