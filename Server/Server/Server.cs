﻿using System.Net.Sockets;
using System.Text;
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
        public List<UserKey> UserKeys { get; set; }
        public List<UserSocket> UserSockets { get; set; }
        public string Address { get; set; } = string.Empty;
        public int Port { get; set; } = 3000;
        public bool Running { get; set; } = false;

        public Server(string address, int port)
        {
            this.Socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
            this.UserKeys = new List<UserKey>();
            this.UserSockets = new List<UserSocket>();
            this.Address = address;
            this.Port = port;
        }

        public void Run()
        {
            Socket? client = this.Socket.Accept();
            Console.WriteLine("EndPoint connected: {0}", client.RemoteEndPoint);
            Thread? clientThread = new Thread(() => this.Communicate(client));
            clientThread.Start();
        }

        public void Communicate(Socket client)
        {
            while (this.Running)
            {
                if (!IsConnected(client)) break;

                byte[]? buffer = new byte[2048];
                int bytes = client.Receive(buffer, SocketFlags.None);

                if (bytes == 0)
                {
                    Console.WriteLine("EndPoint connection closed: {0}", client.RemoteEndPoint);
                    var userSocket = this.UserSockets.FirstOrDefault(us => us.Socket.RemoteEndPoint == client.RemoteEndPoint);
                    var userKey = this.UserKeys.FirstOrDefault(uk => uk.User == userSocket.User);
                    this.UserSockets.Remove(userSocket);
                    this.UserKeys.Remove(userKey);
                    client.Shutdown(SocketShutdown.Both);
                    client.Close();
                    break;
                }

                if (bytes > 0)
                {
                    int nullIndex = Array.FindIndex(buffer, b => b == 0x00);

                    if (nullIndex > -1)
                    {
                        byte[] newBuffer = new byte[nullIndex];
                        Array.Copy(buffer, newBuffer, nullIndex);
                        buffer = newBuffer;
                    }

                    string? receiverJson = Encoding.ASCII.GetString(buffer);
                    MessageFormat? format = System.Text.Json.JsonSerializer.Deserialize<MessageFormat>(receiverJson);

                    if (format == null)
                    {
                        Console.WriteLine("SocketMessageFormatException");
                        break;
                    }

                    switch (format.Flag)
                    {
                        case MessageFormat.PackageType.Username:
                            {
                                this.UserKeys.Add(new UserKey { User = format.Sender, Key = format.RsaPublicKey });
                                this.UserSockets.Add(new UserSocket { User = format.Sender, Socket = client });
                                Console.WriteLine("{0} joined", format.Sender);

                                if (this.UserKeys.Count() > 1)
                                {
                                    // Notifica a tutti dell'arrivo del nuovo Client mandando Nome e Chiave Pubblica

                                    var socketsExceptNew = this.UserSockets.Where(uk => uk.User != format.Sender).ToList();

                                    MessageFormat? join = new MessageFormat
                                    {
                                        Flag = MessageFormat.PackageType.Join,
                                        Sender = format.Sender,
                                        RsaPublicKey = format.RsaPublicKey
                                    };

                                    string? jsonJoin = System.Text.Json.JsonSerializer.Serialize(join);
                                    byte[]? bufferJoin = Encoding.ASCII.GetBytes(jsonJoin);
                                    socketsExceptNew.ForEach(uk => uk.Socket.Send(bufferJoin));

                                    // Notifica il nuovo Client dell'esistenza di altri utenti inviando la lista di Nomi e Chiavi Pubbliche

                                    MessageFormat? update = new MessageFormat
                                    {
                                        Flag = MessageFormat.PackageType.Update,
                                        UserKeys = this.UserKeys.Where(uk => uk.User != format.Sender).ToList()
                                    };

                                    string? jsonUpdate = System.Text.Json.JsonSerializer.Serialize(update);
                                    byte[]? bufferUpdate = Encoding.UTF8.GetBytes(jsonUpdate);
                                    client.Send(bufferUpdate);
                                }

                                break;
                            }
                        case MessageFormat.PackageType.Message:
                            {
                                var receiver = UserSockets.FirstOrDefault(us => us.User == format.Receiver.ToString());

                                if (receiver == null)
                                {
                                    Console.WriteLine("Receiver not found");
                                    break;
                                }

                                receiver.Socket.Send(buffer);
                                break;
                            }
                    }

                    format.Dispose();
                }
            }

            client.Shutdown(SocketShutdown.Both);
            client.Close();
            Console.WriteLine("EndPoint connection closed: {0}", client.RemoteEndPoint);
        }

        public static bool IsConnected(Socket socket)
        {
            return !(socket.Poll(1, SelectMode.SelectRead) && socket.Available == 0);
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
