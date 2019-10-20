using System;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Principal;
using System.Text;

namespace negclient
{
    public class Program
    {
        static TcpClient client = null;

        public static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("usage: negclient <serverHostNameOrIPAddress> <port> <targetName>");
                return;
            }

            string server = args[0];
            int port = int.Parse(args[1]);
            string target = args[2];

            client = new TcpClient();
            client.Connect(server, port);
            Console.WriteLine($"Client connected to {server}:{port}");

            // Ensure the client does not close when there is still data to be sent to the server.
            client.LingerState = (new LingerOption(true, 0));

            // Request authentication.
            NetworkStream clientStream = client.GetStream();
            var authStream = new NegotiateStream(clientStream, false);
            Console.Write("Client waiting for authentication...");
            authStream.AuthenticateAsClient(
                CredentialCache.DefaultNetworkCredentials,
                target,
                ProtectionLevel.EncryptAndSign,
                TokenImpersonationLevel.Identification);
            Console.WriteLine("done.");
            DisplayProperties(authStream);

            // Send a message to the server.
            var writer = new StreamWriter(authStream);
            var clientMessage = new string('A', 65536);
            byte[] message = Encoding.UTF8.GetBytes(clientMessage);
            authStream.Write(message, 0, message.Length);
            Console.WriteLine("Sent {0} bytes.", message.Length);

            // Close the client connection.
            authStream.Close();
            Console.WriteLine("Closing client.");
        }
        public static void DisplayProperties(NegotiateStream stream)
        {
            Console.WriteLine("IsAuthenticated: {0}", stream.IsAuthenticated);
            Console.WriteLine("IsMutuallyAuthenticated: {0}", stream.IsMutuallyAuthenticated);
            Console.WriteLine("IsEncrypted: {0}", stream.IsEncrypted);
            Console.WriteLine("IsSigned: {0}", stream.IsSigned);
            Console.WriteLine("IsServer: {0}", stream.IsServer);
            Console.WriteLine("ImpersonationLevel: {0}", stream.ImpersonationLevel);
            Console.WriteLine("ServerIdentity.AuthenticationType: {0}", stream.RemoteIdentity.AuthenticationType);
            Console.WriteLine("ServerIdentity.IsAuthenticated: {0}", stream.RemoteIdentity.IsAuthenticated);
            Console.WriteLine("ServerIdentity.Name: {0}", stream.RemoteIdentity.Name);
        }
    }
}
