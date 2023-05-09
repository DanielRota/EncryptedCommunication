using System.Net;
using System.Net.Sockets;

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

            Console.WriteLine("########################################");
            Console.WriteLine("### Encrypted Communication - Server ###");
            Console.WriteLine("########################################\n");

            try
            {
                server.AcceptRequests();
            }
            catch (SocketException se)
            {
                Console.WriteLine("\nUnexpected exception : {0}", se.ToString());
                server.Running = false;
            }
            catch (Exception e)
            {
                Console.WriteLine("\nUnexpected exception : {0}", e.ToString());
                server.Running = false;
            }

            Console.WriteLine("Server stopped. Press any key to exit...");
            Console.ReadKey();
        }
    }
}
