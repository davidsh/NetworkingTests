// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Linq;
using System.Net.Test.Common;
using System.Security.Authentication;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

using Xunit;
using Xunit.Abstractions;

namespace System.Net.Security.Tests
{
    public class NegotiateStreamTest
    {
        private readonly ITestOutputHelper _output;

        public NegotiateStreamTest(ITestOutputHelper output)
        {
            _output = output;
        }

        public static readonly object[][] SuccessCasesMemberData =
        {
            new object[] { new NetworkCredential("user1", "password"), true, "HOST/localhost" },
            new object[] { new NetworkCredential("user1", "password"), true, "HOST/linuxclient.linux.contoso.com" },
            //new object[] { new NetworkCredential("user1", "password"), false, "UNKNOWNHOST/localhost" },
            //new object[] { new NetworkCredential("user3ntlm", "password"), false, "HOST/localhost" },
            //new object[] { new NetworkCredential("user3ntlm", "password"), false, "NEWSERVICE/localhost" },
            //new object[] { CredentialCache.DefaultNetworkCredentials, true, "HOST/localhost" },
            //new object[] { CredentialCache.DefaultNetworkCredentials, true, "HOST/kdc.linux.contoso.com" },
        };

        [Theory]
        [MemberData(nameof(SuccessCasesMemberData))]
        public async Task StreamToStream_Authentication_Success(
            NetworkCredential creds, bool isKerberos, string target)
        {
            var network = new VirtualNetwork();

            using (var clientStream = new VirtualNetworkStream(network, isServer: false))
            using (var serverStream = new VirtualNetworkStream(network, isServer: true))
            using (var client = new NegotiateStream(clientStream))
            using (var server = new NegotiateStream(serverStream))
            {
                Assert.False(client.IsAuthenticated);
                Assert.False(server.IsAuthenticated);

                Task[] auth = new Task[2];
                auth[0] = client.AuthenticateAsClientAsync(creds, target);
                auth[1] = server.AuthenticateAsServerAsync();

                await TestConfiguration.WhenAllOrAnyFailedWithTimeout(auth);

                VerifyStreamProperties(client, isServer: false, isKerberos, target);

                string remoteName = (creds == CredentialCache.DefaultNetworkCredentials) ?
                    TestConfiguration.DefaultNetworkCredentials.UserName : creds.UserName;
                if (isKerberos) remoteName += "@" + TestConfiguration.Realm;
                //VerifyStreamProperties(server, isServer: true, isKerberos, remoteName);
            }
        }
        
        private void VerifyStreamProperties(NegotiateStream stream, bool isServer, bool isKerberos, string remoteName)
        {
            Assert.True(stream.IsAuthenticated);
            Assert.Equal(TokenImpersonationLevel.Identification, stream.ImpersonationLevel);
            Assert.True(stream.IsEncrypted);
            Assert.Equal(isKerberos, stream.IsMutuallyAuthenticated);
            Assert.Equal(isServer, stream.IsServer);
            Assert.True(stream.IsSigned);
            Assert.False(stream.LeaveInnerStreamOpen);

            IIdentity remoteIdentity = stream.RemoteIdentity;
            Assert.Equal(isKerberos ? "Kerberos" : "NTLM", remoteIdentity.AuthenticationType);
            Assert.True(remoteIdentity.IsAuthenticated);
            _output.WriteLine($"VerifyStreamProperties: remote '{remoteIdentity.Name}'");
            Assert.Equal(remoteName, remoteIdentity.Name);
        }

        public static readonly object[][] FailureCasesMemberData =
        {
            // 'user1' is a valid Kerberos credential. But trying to connect to the server using
            // the 'NEWSERVICE/localhost' SPN is not valid. That SPN, while registered in the overall
            // Kerberos realm, is not registered on this particular server's keytab. So, this test case verifies
            // that SPNEGO won't fallback from Kerberos to NTLM. Instead, it causes an AuthenticationException.
            new object[] { new NetworkCredential("user1", "password"), "NEWSERVICE/localhost" },

            // Invalid Kerberos credential password.
            new object[] { new NetworkCredential("user1", "passwordxx"), "HOST/localhost" },
        };

        [Theory]
        [MemberData(nameof(FailureCasesMemberData))]
        public async Task StreamToStream_Authentication_Failure(NetworkCredential creds, string target)
        {
            var network = new VirtualNetwork();

            using (var clientStream = new VirtualNetworkStream(network, isServer: false))
            using (var serverStream = new VirtualNetworkStream(network, isServer: true))
            using (var client = new NegotiateStream(clientStream))
            using (var server = new NegotiateStream(serverStream))
            {
                Assert.False(client.IsAuthenticated);
                Assert.False(server.IsAuthenticated);

                AuthenticationException ex =
                    await Assert.ThrowsAsync<AuthenticationException>(() => client.AuthenticateAsClientAsync(creds, target));
                Console.WriteLine(ex.InnerException.Message);
            }
        }
    }
}
