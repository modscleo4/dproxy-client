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

using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace DProxyClient
{
    internal static class Program
    {
        private static readonly string ConfigPath =
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DProxy");

        private static readonly string ServerPublicKeyPath = Path.Combine(ConfigPath, "ServerPublicKey.pem");
        private static readonly string ClientPrivateKeyPath = Path.Combine(ConfigPath, "ClientPrivateKey.pem");
        private static readonly string ClientPublicKeyPath = Path.Combine(ConfigPath, "ClientPublicKey.pem");
        private static readonly string ClientTokenPath = Path.Combine(ConfigPath, "Token");
        private static readonly ILogger Logger = Log.Factory.CreateLogger(typeof(Program).Namespace ?? string.Empty);

        /**
         * ConnectionID -> TCP Connection Map
         */
        private static readonly ConcurrentDictionary<uint, TcpClient> Connections = [];

        private static readonly byte[] _readBuffer = new byte[2 << 14];

        private static readonly byte[] _writeBuffer = new byte[2 << 14];

        /// <summary>
        /// Get the server's public key from the file system.
        /// </summary>
        ///
        /// <return>The server's public key.</return>
        private static ECDiffieHellman GetServerPublicKey()
        {
            var serverPublicKey = File.ReadAllText(ServerPublicKeyPath);
            var serverKey       = ECDiffieHellman.Create();
            serverKey.ImportFromPem(serverPublicKey);

            return serverKey;
        }

        /// <summary>
        /// Get the client's key pair from the file system.
        /// </summary>
        ///
        /// <return>The client's key pair.</return>
        private static ECDiffieHellman GetClientKeyPair()
        {
            var clientPrivateKey = File.ReadAllText(ClientPrivateKeyPath);
            var clientKey        = ECDiffieHellman.Create();
            clientKey.ImportFromPem(clientPrivateKey);

            return clientKey;
        }

        /// <summary>
        /// Create a new client key pair and save it to the file system.
        /// </summary>
        ///
        /// <return>The client's key pair.</return>
        private static ECDiffieHellman CreateClientKeyPair()
        {
            var clientKey        = ECDiffieHellman.Create(ECCurve.CreateFromFriendlyName("secp384r1"));
            var clientPublicKey  = clientKey.ExportSubjectPublicKeyInfoPem();
            var clientPrivateKey = clientKey.ExportPkcs8PrivateKeyPem();

            File.WriteAllText(ClientPrivateKeyPath, clientPrivateKey);
            File.WriteAllText(ClientPublicKeyPath, clientPublicKey);

            return clientKey;
        }

        /// <summary>
        /// Read data from the TCP endpoints and relay it to the server.
        /// </summary>
        ///
        /// <param name="stream">The server's network stream.</param>
        /// <param name="cipher">The cipher used to encrypt/decrypt the data.</param>
        private static async Task ReadSockets(NetworkStream stream, AesGcm cipher)
        {
            using var _ = Logger.BeginScope(nameof(ReadSockets));

            try {
                // Read the data from the TCP endpoints and relay it to the server.
                foreach (var (connectionId, client) in Connections) {
                    while (client.Available > 0) {
                        Logger.LogDebug("Reading {Bytes} bytes from {RemoteEndPoint}...", client.Available,
                            client.Client.RemoteEndPoint);
                        var bytesRead = await client.GetStream().ReadAsync(_readBuffer, CancellationToken.None);
                        if (bytesRead == 0) {
                            break;
                        }

                        // Encrypt the data with the shared secret.
                        var iv = new byte[12];
                        RandomNumberGenerator.Fill(iv);
                        var cipherText = new byte[bytesRead];
                        var authTag    = new byte[16];
                        cipher.Encrypt(iv, _readBuffer.AsSpan(0, bytesRead), cipherText, authTag);

                        // Send the data to the server.
                        Logger.LogDebug("Sending {Bytes} bytes of data to the server...", bytesRead);
                        await Client.SendData(stream, connectionId, iv, cipherText, authTag);
                    }
                }
            }
            catch (Exception e) {
                Logger.LogError(e, "Failed to read data from the TCP endpoints.");
            }
        }

        /// <summary>
        /// Handle a packet received from the server.
        /// </summary>
        ///
        /// <param name="stream">The server's network stream.</param>
        /// <param name="header">The incoming packet header.</param>
        /// <param name="cipher">The cipher used to encrypt/decrypt the data.</param>
        private static async Task HandleServerPacket(NetworkStream stream, DProxyHeader header, AesGcm cipher)
        {
            using var _ = Logger.BeginScope(nameof(StartSocket));

            switch (header.Type) {
                case DProxyPacketType.CONNECT: {
                    var connect = await Client.ReadConnect(stream, header);
                    Logger.LogInformation("Connecting to {Destination}:{Port}...", connect.Destination, connect.Port);

                    if (Connections.ContainsKey(connect.ConnectionId)) {
                        await Client.SendError(stream, DProxyError.INVALID_CONNECTION);
                        return;
                    }

                    try {
                        var client = new TcpClient();
                        await client.ConnectAsync(connect.Destination, connect.Port);

                        Connections[connect.ConnectionId] = client;

                        await Client.SendConnected(stream, connect.ConnectionId);
                    }
                    catch (SocketException e) {
                        Logger.LogError(e, "Failed to connect to {Destination}:{Port}.", connect.Destination,
                            connect.Port);
                        await Client.SendError(stream, DProxyError.CONNECTION_FAILED);
                    }

                    break;
                }

                case DProxyPacketType.DISCONNECT: {
                    var disconnect = await Client.ReadDisconnect(stream, header);

                    if (Connections.TryGetValue(disconnect.ConnectionId, out var client)) {
                        try {
                            Logger.LogInformation("Disconnecting from {Address}...", client.Client.RemoteEndPoint);
                            client.Close();
                        }
                        catch (SocketException) {
                            //
                        }

                        Connections.Remove(disconnect.ConnectionId, out var _);
                        await Client.SendDisconnected(stream, disconnect.ConnectionId);
                    }
                    else {
                        await Client.SendError(stream, DProxyError.INVALID_CONNECTION);
                    }


                    break;
                }

                case DProxyPacketType.DATA: {
                    var data = await Client.ReadData(stream, header);

                    if (Connections.TryGetValue(data.ConnectionId, out var client)) {
                        try {
                            // Decrypt the data with the shared secret.
                            cipher.Decrypt(data.IV, data.Ciphertext, data.AuthenticationTag,
                                new Span<byte>(_writeBuffer, 0, data.Ciphertext.Length));

                            // Send the data to the TCP endpoint.
                            Logger.LogDebug("Sending {Bytes} bytes of data to {RemoteEndPoint}...",
                                data.Ciphertext.Length, client.Client.RemoteEndPoint);
                            await client.GetStream().WriteAsync(_writeBuffer.AsMemory(0, data.Ciphertext.Length));
                        }
                        catch (AuthenticationTagMismatchException e) {
                            Logger.LogError(e, "Failed to decrypt data from the DProxy Server.");
                            throw new SocketException((int)SocketError.ConnectionReset);
                        }
                        catch (SocketException e) {
                            Logger.LogError(e, "Failed to relay data to the TCP endpoint.");
                            await Client.SendError(stream, DProxyError.CONNECTION_FAILED);
                        }
                        catch (IOException e) {
                            Logger.LogError(e, "Failed to relay data to the TCP endpoint.");
                            await Client.SendError(stream, DProxyError.CONNECTION_CLOSED);
                        }
                    }
                    else {
                        await Client.SendError(stream, DProxyError.INVALID_CONNECTION);
                    }

                    break;
                }

                case DProxyPacketType.HEARTBEAT: {
                    var heartbeat = await Client.ReadHeartbeat(stream, header);
                    Logger.LogTrace("Received a heartbeat from the server: {Timestamp}.", heartbeat.Timestamp);
                    await Client.SendHeartbeatResponse(stream,
                        (ulong)new DateTimeOffset(DateTime.UtcNow).ToUnixTimeMilliseconds());
                    break;
                }

                case DProxyPacketType.HEARTBEAT_RESPONSE:
                    var heartbeatResponse = await Client.ReadHeartbeatResponse(stream, header);
                    Logger.LogTrace("Received a heartbeat response from the server: {Timestamp}.",
                        heartbeatResponse.Timestamp);
                    break;

                default:
                    Logger.LogWarning("Received an invalid packet type: {Type}.", header.Type);
                    break;
            }
        }

        private static async Task ReadServerSocket(NetworkStream stream, AesGcm cipher)
        {
            if (stream.Socket.Available == 0) {
                if (Connections.IsEmpty)
                    await Client.SendHeartbeat(stream,
                        (ulong)new DateTimeOffset(DateTime.UtcNow).ToUnixTimeMilliseconds());

                return;
            }

            var incomingHeader = await Client.GetPacketHeader(stream, false);
            await HandleServerPacket(stream, incomingHeader, cipher);
        }

        /// <summary>
        /// Start the Socket connection with the server.
        /// </summary>
        ///
        /// <param name="serverHost">The server's host name or IP address.</param>'
        /// <param name="serverKey">The server's public key.</param>
        /// <param name="clientKey">The client's key pair.</param>
        /// <return>Whether the connection was successful.</return>
        ///
        private static async Task<bool> StartSocket(string serverHost, ECDiffieHellman serverKey,
            ECDiffieHellman clientKey)
        {
            using var _ = Logger.BeginScope(nameof(StartSocket));

            var socket = new TcpClient();

            foreach (var connection in Connections) {
                Logger.LogInformation("Closing connection {ConnectionId}...", connection.Key);
                connection.Value.Close();
            }

            Connections.Clear();

            try {
                // Establish a connection with the server.
                await socket.ConnectAsync(serverHost, 8081);
                var stream = socket.GetStream();

                // Derive the shared secret and the CEK.
                var sharedSecret = clientKey.DeriveRawSecretAgreement(serverKey.PublicKey);
                var cek          = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32);
                Logger.LogDebug("Shared secret: {SharedSecret}", BitConverter.ToString(sharedSecret).Replace("-", ""));
                Logger.LogDebug("CEK: {CEK}", BitConverter.ToString(cek).Replace("-", ""));

                // Start the handshake
                // Send the public key to the server.
                await Client.StartHandshake(stream, clientKey);

                // Process the response from the server.
                var handshakeResponseHeader = await Client.GetPacketHeader(stream);
                if (!Client.ValidateHeader(handshakeResponseHeader, DProxyPacketType.HANDSHAKE_RESPONSE)) {
                    return false;
                }

                // Fetch the iv, cipher text and authentication tag from the server.
                var handshakeResponse = await Client.ReadHandshakeResponse(stream, handshakeResponseHeader);
                Logger.LogDebug("IV: {IV}", BitConverter.ToString(handshakeResponse.IV).Replace("-", ""));
                Logger.LogDebug("Cipher Text: {CipherText}",
                    BitConverter.ToString(handshakeResponse.Ciphertext).Replace("-", ""));
                Logger.LogDebug("Authentication Tag: {AuthenticationTag}",
                    BitConverter.ToString(handshakeResponse.AuthenticationTag).Replace("-", ""));

                // Decrypt the cipher text with the shared secret.
                var cipher    = new AesGcm(cek, 16);
                var plainText = new byte[handshakeResponse.Ciphertext.Length];
                cipher.Decrypt(handshakeResponse.IV, handshakeResponse.Ciphertext, handshakeResponse.AuthenticationTag,
                    plainText);
                Logger.LogDebug("Plain Text: {PlainText}", BitConverter.ToString(plainText).Replace("-", ""));

                // Send the plain text back to the server.
                await Client.SendHandshakeFinal(stream, plainText);

                // Check if the server accepted the message.
                var handshakeResultHeader = await Client.GetPacketHeader(stream);
                if (!Client.ValidateHeader(handshakeResultHeader, DProxyPacketType.HANDSHAKE_FINALIZED)) {
                    return false;
                }

                Logger.LogInformation("The handshake was successful.");
                while (true) {
                    if (!stream.Socket.Connected) {
                        throw new SocketException((int)SocketError.NotConnected);
                    }

                    var waitList = new List<Socket>(Connections.Count + 1);
                    waitList.Add(stream.Socket);
                    waitList.AddRange(
                        from connection in Connections.Select((t, i) => Connections.Values.ElementAt(i))
                        where connection.Connected
                        select connection.GetStream().Socket
                    );

                    // Wait for data to be available on any of the TCP endpoints.
                    Socket.Select(waitList, null, null, TimeSpan.FromSeconds(30));

                    await Task.WhenAll(ReadServerSocket(stream, cipher), ReadSockets(stream, cipher));
                }
            }
            finally {
                // Close all the TCP connections when the thread is terminated.
                foreach (var connection in Connections) {
                    connection.Value.Close();

                    try {
                        if (socket.Connected && socket.GetStream().CanWrite) {
                            await Client.SendDisconnected(socket.GetStream(), connection.Key);
                        }
                    }
                    catch (IOException e) {
                        Logger.LogError(e, "Failed to send a disconnect message to the server.");
                    }
                    catch (SocketException e) {
                        Logger.LogError(e, "Failed to send a disconnect message to the server.");
                    }
                }

                Connections.Clear();
                socket.Close();
            }
        }

        private static async Task Main(string[] args)
        {
            using var _ = Logger.BeginScope(nameof(Main));

            try {
                ECDiffieHellman serverKey;
                ECDiffieHellman clientKey;

                if (!File.Exists(ConfigPath)) {
                    Directory.CreateDirectory(ConfigPath);
                }

                if (!File.Exists(ServerPublicKeyPath)) {
                    Logger.LogInformation("Fetching server's public key from Key Exchange Server...");
                    serverKey = await KeyServer.GetServerPublicKeyFromExchangeServer();

                    // Save the server's public key to the file system.
                    await File.WriteAllTextAsync(ServerPublicKeyPath, serverKey.ExportSubjectPublicKeyInfoPem());
                }
                else {
                    serverKey = GetServerPublicKey();
                }

                if (!File.Exists(ClientPrivateKeyPath)) {
                    clientKey = CreateClientKeyPair();

                    // Send Public Key to Key Exchange Server
                    Logger.LogInformation("Sending client's public key to Key Exchange Server...");
                    await KeyServer.SendClientPublicKeyToExchangeServer(clientKey,
                        (await File.ReadAllTextAsync(ClientTokenPath)).Trim());
                }
                else {
                    clientKey = GetClientKeyPair();
                }

                // Retry the connection if the server closed it prematurely.
                while (true) {
                    try {
                        if (!await StartSocket("localhost", serverKey, clientKey)) {
                            // Stop retrying if the server rejected the message.
                            break;
                        }
                    }
                    catch (Exception e) when
                        (e is SocketException or IOException or AuthenticationTagMismatchException) {
                        Logger.LogError(e, "Failed to connect to the DProxy Server.");

                        await Task.Delay(5000);
                    }
                }
            }
            catch (Exception e) {
                Logger.LogError(e, "An unhandled exception occurred.");
            }
        }
    }
}