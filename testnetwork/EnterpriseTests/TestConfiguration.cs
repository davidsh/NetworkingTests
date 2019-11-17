// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Net.Security.Tests
{
    internal static class TestConfiguration
    {
        public const string Realm = "LINUX.CONTOSO.COM";
        public const string Domain = "LINUX";
        public const string NegotiateServerHost = "linuxweb.linux.contoso.com";
        public const int NegotiateServerPort = 8080;

        public static NetworkCredential DefaultNetworkCredentials { get { return new NetworkCredential("defaultcred", "password"); } }
    }
}
