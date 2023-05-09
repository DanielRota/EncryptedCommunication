using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Server;

namespace ServerAsymmetricCommunication
{
    public class Server
    {
        public Socket Socket { get; set; }
        public List<Tuple<string, byte[], Socket>> ClientSockets { get; set; }
        public List<Socket> Sockets { get; set; }
        public string Address { get; set; } = string.Empty;
        public int Port { get; set; }
        public bool Running { get; set; } = false;

        public Server(string address, int port)
        {
            this.Socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            this.ClientSockets = new List<Tuple<string, byte[], Socket>>();
            this.Sockets = new List<Socket>();
            this.Address = address;
            this.Port = port;
        }

        public void AcceptRequests()
        {
            while (this.Running)
            {
                var client = this.Socket.AcceptAsync().Result;
                Console.WriteLine("Connected to EndPoint: {0}", client.RemoteEndPoint);
                this.Sockets.Add(client);
                var thread = new Thread(() => this.Communicate(client));
                thread.Start();
            }
        }

        public void Communicate(Socket client)
        {
            while (this.Running)
            {
                if (!IsConnected(client)) break;

                byte[]? buffer = new byte[2048];
                int bytes = client.Receive((Span<byte>)buffer, SocketFlags.None);
                int nullIndex = Array.FindIndex(buffer, b => b == 0x00);

                if (nullIndex > -1)
                {
                    byte[] newBuffer = new byte[nullIndex];
                    Array.Copy(buffer, newBuffer, nullIndex);
                    buffer = newBuffer;
                }

                string? receivedJson = Encoding.ASCII.GetString(buffer);
                SocketMessageFormat? format = JsonSerializer.Deserialize<SocketMessageFormat>(receivedJson);

                if (format == null)
                {
                    Console.WriteLine($"SocketMessageFormatException");
                    break;
                }

                if (bytes > 0)
                {
                    switch (format.Flag)
                    {
                        case SocketMessageFormat.SocketMessageFlag.Username:
                            {
                                this.ClientSockets.Add(Tuple.Create(format.Sender, format.RsaPublicKey, client));
                                Console.WriteLine("{0} joined", format.Sender);

                                //if (this.ClientSockets.Any())
                                //{
                                //    foreach (var clientSocket in this.ClientSockets)
                                //    {
                                //        var updateCollection = new SocketMessageFormat
                                //        {
                                //            Flag = SocketMessageFormat.SocketMessageFlag.UpdateUsersCollection,
                                //            ForeignUser = clientSocket.Item1,
                                //            RsaPublicKey = clientSocket.Item2
                                //        };

                                //        string? jsonUpdate = JsonSerializer.Serialize(updateCollection);
                                //        client.Send(Encoding.ASCII.GetBytes(jsonUpdate));
                                //    }
                                //}

                                var join = new SocketMessageFormat
                                {
                                    Flag = SocketMessageFormat.SocketMessageFlag.Username,
                                    Sender = format.Sender,
                                    RsaPublicKey = format.RsaPublicKey
                                };

                                if (join == null)
                                {
                                    Console.WriteLine($"SocketMessageFormatException");
                                    break;
                                }

                                string? json = JsonSerializer.Serialize(format);
                                this.ClientSockets.Where(cs => cs.Item1 != format.Sender).ToList().ForEach(cs => cs.Item3.Send(Encoding.ASCII.GetBytes(json)));
                                break;
                            }

                        case SocketMessageFormat.SocketMessageFlag.Message:
                            {
                                var receiver = ClientSockets.FirstOrDefault(cs => cs.Item1 == format.Receiver.ToString());
                                receiver.Item3.Send(buffer);
                                break;
                            }
                    }
                }

                client.Shutdown(SocketShutdown.Both);
                client.Close();
                Console.WriteLine("Connection closed.");
            }
        }

        public static bool IsConnected(Socket socket)
        {
            try
            {
                return !(socket.Poll(1, SelectMode.SelectRead) && socket.Available == 0);
            }
            catch (SocketException)
            {
                return false;
            }
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
