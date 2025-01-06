using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace DProxyClient
{
    class KeyServer
    {
        public static async Task<ECDiffieHellman> GetServerPublicKeyFromExchangeServer()
        {
            var http = new HttpClient();
            var res = await http.GetAsync("http://localhost:8080/key-exchange");
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
            var http = new HttpClient();
            http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            var content = new StringContent(clientPublicKey, Encoding.UTF8, "application/x-pem-file");

            var res = await http.PostAsync("http://localhost:8080/key-exchange", content);
            if (!res.IsSuccessStatusCode) {
                throw new Exception($"Failed to send the public key to the Key Exchange Server: {res.Content}.");
            }
        }
    }
}
