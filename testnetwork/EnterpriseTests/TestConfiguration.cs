// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using Xunit;

namespace System.Net.Security.Tests
{
    internal static class TestConfiguration
    {
        public const int PassingTestTimeoutMilliseconds = 4 * 60 * 1000;
        public const int FailingTestTimeoutMiliseconds = 250;

        public const string Realm = "LINUX.CONTOSO.COM";
        public const string Domain = "LINUX";

        public static NetworkCredential DefaultNetworkCredentials { get { return new NetworkCredential("defaultcred", "password"); } }

        public static Task WhenAllOrAnyFailedWithTimeout(params Task[] tasks)
            => tasks.WhenAllOrAnyFailed(PassingTestTimeoutMilliseconds);
    }
}
