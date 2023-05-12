using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace ServerAsymmetricCommunication
{
    internal static class Program
    {
        private static void Main(string[] args)
        {
            Server? server = new Server("localhost", 3000);

            try
            {
                IPAddress? address = Dns.GetHostEntry(server.Address).AddressList[0];
                IPEndPoint? endPoint = new IPEndPoint(address, server.Port);

                server.Socket.Bind(endPoint);
                server.Socket.Listen();
                server.Running = true;
            }
            catch (SocketException se)
            {
                Console.WriteLine("\nUnexpected exception : {0}", se.ToString());
                server.Running = false;
            }

            Console.WriteLine("############################################################################");
            Console.WriteLine("###################                                    #####################");
            Console.WriteLine("###############      ServerSide RSA/AES Communication      #################");
            Console.WriteLine("################             Communication log            ##################");
            Console.WriteLine("#####################                                #######################");
            Console.WriteLine("############################################################################\n");
            Console.WriteLine("Waiting for connections...");

            server.Socket.Listen();

            while (server.Running)
            {
                try
                {
                    server.Run();
                }
                catch (SocketException se) when (se.SocketErrorCode == SocketError.TimedOut)
                {
                    Console.WriteLine("\nUnexpected exception : {0}", se.ToString());
                }
                catch (CryptographicException ce)
                {
                    Console.WriteLine("\nCryptographicException: {0}", ce.ToString());
                }
                catch (Exception e)
                {
                    Console.WriteLine("\nUnexpected exception : {0}", e.ToString());
                }
            }

            Console.WriteLine("Server stopped. Press any key to exit...");
            Console.ReadKey();
        }
    }
}
