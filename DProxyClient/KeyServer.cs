// Copyright 2025 Dhiego Cassiano Fogaça Barbosa
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace DProxyClient;

class KeyServer
{
    private static readonly string ServerAddress = Assembly.GetExecutingAssembly().GetCustomAttribute<ServerAddressAttribute>()?.Value ?? "localhost";
    public static readonly string KeyExchangeServer = $"http://{ServerAddress}:8080";

    public static async Task<ECDiffieHellman> GetServerPublicKeyFromExchangeServer()
    {
        var http = new HttpClient();
        var res  = await http.GetAsync($"{KeyExchangeServer}/key-exchange");
        if (!res.IsSuccessStatusCode) {
            throw new Exception($"Failed to fetch the server's public key from the Key Exchange Server: {res.Content}.");
        }

        var serverPublicKey = await res.Content.ReadAsStringAsync();

        var serverKey = ECDiffieHellman.Create();
        serverKey.ImportFromPem(serverPublicKey);

        return serverKey;
    }

    public static async Task SendClientPublicKeyToExchangeServer(ECDiffieHellman clientKey, string token)
    {
        var clientPublicKey = clientKey.ExportSubjectPublicKeyInfoPem();
        var http            = new HttpClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        var content = new StringContent(clientPublicKey, Encoding.UTF8, "application/x-pem-file");

        var res = await http.PostAsync($"{KeyExchangeServer}/key-exchange", content);
        if (!res.IsSuccessStatusCode) {
            throw new Exception($"Failed to send the public key to the Key Exchange Server: {res.Content}.");
        }
    }
}
