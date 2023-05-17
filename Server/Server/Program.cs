using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace ServerAsymmetricCommunication
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            Console.WriteLine("############################################################################");
            Console.WriteLine("###################                                    #####################");
            Console.WriteLine("###############      ServerSide RSA/AES Communication      #################");
            Console.WriteLine("################             Communication log            ##################");
            Console.WriteLine("#####################                                #######################");
            Console.WriteLine("############################################################################\n");

            Server? server = new Server("localhost", 3000);
            IPAddress? address = Dns.GetHostEntry(server.Address).AddressList[0];
            IPEndPoint? endPoint = new IPEndPoint(address, server.Port);

            try
            {
                server.Socket.Bind(endPoint);
                server.Running = true;
                server.Socket.Listen();

                while (server.Running)
                {
                    Console.WriteLine("Waiting for a connection...");
                    Socket? client = server.Socket.Accept();
                    Console.WriteLine("EndPoint connected: {0}", client.RemoteEndPoint);
                    Thread? clientThread = new Thread(() => server.Communicate(client));
                    clientThread.Start();
                }
            }
            catch (CryptographicException ce)
            {
                Console.WriteLine("\nCryptographicException: {0}", ce.ToString());
            }
            catch (SocketException se)
            {
                Console.WriteLine("\nUnexpected exception : {0}", se.ToString());
            }    
            catch (Exception e)
            {
                Console.WriteLine("\nUnexpected exception : {0}", e.ToString());
            }

            Console.WriteLine("Server stopped. Press any key to exit...");
            Console.Read();
        }
    }
}
