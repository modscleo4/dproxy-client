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
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace DProxyClient
{
    [AttributeUsage(AttributeTargets.Assembly)]
    public sealed class ServerAddressAttribute : Attribute
    {
        public string Value { get; set; }
        public ServerAddressAttribute(string value)
        {
            Value = value;
        }
    }

    internal static class IPAddressExtensions
    {
        public static string ToStringFormatted(this IPAddress address)
        {
            if (address.IsIPv4MappedToIPv6) {
                return address.MapToIPv4().ToString();
            }

            return address.AddressFamily == AddressFamily.InterNetworkV6 ? $"[{address}]" : address.ToString();
        }
    }

    internal static class Program
    {
        private static readonly string ServerAddress = Assembly.GetExecutingAssembly().GetCustomAttribute<ServerAddressAttribute>()?.Value ?? "localhost";

        private static readonly string ConfigPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DProxy");

        private static readonly string ServerPublicKeyPath = Path.Combine(ConfigPath, "ServerPublicKey.pem");
        private static readonly string ClientPrivateKeyPath = Path.Combine(ConfigPath, "ClientPrivateKey.pem");
        private static readonly string ClientPublicKeyPath = Path.Combine(ConfigPath, "ClientPublicKey.pem");
        private static readonly string ClientTokenPath = Path.Combine(ConfigPath, "Token");
        private static readonly ILogger Logger = Log.Factory.CreateLogger(typeof(Program).Namespace ?? string.Empty);

        /**
         * ConnectionID -> TCP Connection Map
         */
        private static readonly ConcurrentDictionary<uint, Socket> Connections = [];
        private static readonly ConcurrentDictionary<uint, Task> ConnectionTasks = [];
        private static readonly ConcurrentDictionary<uint, byte[]> ConnectionReadBuffer = [];
        private static readonly ConcurrentDictionary<uint, byte[]> ConnectionWriteBuffer = [];

        private static readonly bool EncryptData = true;

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
        /// Read data from the connected TCP Socket and send it to the server.
        /// </summary>
        ///
        /// <param name="stream">The server's network stream.</param>
        /// <param name="cipher">The cipher used to encrypt/decrypt the data.</param>
        /// <param name="connectionId">The connection ID.</param>
        /// <param name="socket">The connected TCP Socket.</param>
        /// <returns>Whether the TCP Socket is still connected or not.</returns>
        private static async Task<bool> ReadConnectedSocket(NetworkStream stream, AesGcm cipher, uint connectionId, Socket socket)
        {
            var buffer = ConnectionReadBuffer[connectionId];

            try {
                var bytesRead = await socket.ReceiveAsync(buffer, CancellationToken.None);
                if (bytesRead == 0) {
                    // The method returns zero (0) only if
                    //   zero bytes were requested
                    //   or if no more bytes are available because the peer socket performed a graceful shutdown.
                    return false;
                }

                if (!EncryptData) {
                    // Send the data to the server.
                    Logger.LogTrace("Sending {Bytes} bytes of data to the server...", bytesRead);
                    await Client.SendData(stream, connectionId, buffer.AsSpan(0, bytesRead).ToArray());
                    return true;
                }

                // Encrypt the data with the shared secret.
                var iv = new byte[12];
                RandomNumberGenerator.Fill(iv);
                var cipherText = new byte[bytesRead];
                var authTag    = new byte[16];
                cipher.Encrypt(iv, buffer.AsSpan(0, bytesRead), cipherText, authTag);

                // Send the data to the server.
                Logger.LogTrace("Sending {Bytes} bytes of data to the server...", bytesRead);
                await Client.SendEncryptedData(stream, connectionId, iv, cipherText, authTag);

                return true;
            } catch (IOException e) {
                Logger.LogError(e, "Failed to read data from the TCP endpoints.");
                return true;
            } catch (Exception e) when (e is ObjectDisposedException or InvalidOperationException) {
                Logger.LogError(e, "Failed to read data from the TCP endpoints.");
                return false;
            }
        }

        /// <summary>
        /// Handle a packet received from the server.
        /// </summary>
        ///
        /// <param name="stream">The server's network stream.</param>
        /// <param name="cek">The content encryption key used to encrypt/decrypt the data.</param>
        /// <param name="header">The incoming packet header.</param>
        private static async Task HandleServerPacket(NetworkStream stream, byte[] cek, DProxyHeader header)
        {
            using var _ = Logger.BeginScope(nameof(StartSocket));

            switch (header.Type) {
                case DProxyPacketType.CONNECT: {
                    var packet = await Client.ReadConnect(stream, header);
                    Logger.LogDebug("Connection {ConnectionId}: {Destination}:{Port}.", packet.ConnectionId, packet.Destination, packet.Port);

                    if (Connections.ContainsKey(packet.ConnectionId)) {
                        await Client.SendError(stream, DProxyError.INVALID_CONNECTION);
                        return;
                    }

                    var task = async () => {
                        var cipher = new AesGcm(cek, 16);

                        try {
                            Logger.LogDebug("[{Type}] Connecting {ConnectionId} to {Destination}:{Port}...", packet.ConnectionType, packet.ConnectionId, packet.Destination, packet.Port);
                            using var cts = new CancellationTokenSource();
                            cts.CancelAfter(1000);

                            using var client = new TcpClient();

                            await client.ConnectAsync(packet.Destination, packet.Port, cts.Token);
                            Logger.LogInformation("[{Type}] Connected {ConnectionId} to {Destination}:{Port}.", packet.ConnectionType, packet.ConnectionId, packet.Destination, packet.Port);
                            client.NoDelay = true;
                            client.SendBufferSize = 2 << 14;
                            client.ReceiveBufferSize = 2 << 14;

                            var socket = client.Client;
                            var bndAddr = ((IPEndPoint?)socket.LocalEndPoint)?.Address?.ToStringFormatted() ?? "0.0.0.0";
                            var bndPort = ((IPEndPoint?)socket.LocalEndPoint)?.Port ?? 0;

                            Connections[packet.ConnectionId]           = socket;
                            ConnectionReadBuffer[packet.ConnectionId]  = new byte[2 << 14];
                            ConnectionWriteBuffer[packet.ConnectionId] = new byte[2 << 14];
                            await Client.SendConnected(stream, packet.ConnectionId, bndAddr, (ushort)bndPort);

                            while (true) {
                                if (!stream.Socket.Connected) {
                                    break;
                                }

                                if (!socket.Connected) {
                                    break;
                                }

                                if (!await ReadConnectedSocket(stream, cipher, packet.ConnectionId, socket)) {
                                    break;
                                }

                                await Task.Yield();
                            }

                            Logger.LogDebug("Connection {ConnectionId} terminated.", packet.ConnectionId);
                        } catch (SocketException e) {
                            Logger.LogError(e, "Failed to connect to {Destination}:{Port}.", packet.Destination, packet.Port);
                            await Client.SendDisconnected(stream, packet.ConnectionId, DProxyError.CONNECTION_FAILED);
                        } catch (OperationCanceledException e) {
                            Logger.LogError(e, "Failed to connect to {Destination}:{Port}.", packet.Destination, packet.Port);
                            await Client.SendDisconnected(stream, packet.ConnectionId, DProxyError.CONNECTION_TIMEOUT);
                        } catch (Exception e) {
                            Logger.LogError(e, "Failed to connect to {Destination}:{Port}.", packet.Destination, packet.Port);
                        } finally {
                            Connections.Remove(packet.ConnectionId, out var _);
                            ConnectionTasks.Remove(packet.ConnectionId, out var _);
                            ConnectionReadBuffer.Remove(packet.ConnectionId, out var _);
                            ConnectionWriteBuffer.Remove(packet.ConnectionId, out var _);
                            await Client.SendDisconnected(stream, packet.ConnectionId);
                        }
                    };

                    ConnectionTasks[packet.ConnectionId] = Task.Run(task);
                    break;
                }

                case DProxyPacketType.DISCONNECT: {
                    var packet = await Client.ReadDisconnect(stream, header);

                    if (Connections.TryGetValue(packet.ConnectionId, out var socket)) {
                        try {
                            Logger.LogInformation("Disconnecting from {Address}...", socket.RemoteEndPoint);
                            socket.Close();
                        } catch (SocketException) {
                            //
                        }

                        Connections.Remove(packet.ConnectionId, out var _);
                        ConnectionTasks.Remove(packet.ConnectionId, out var _);
                        ConnectionReadBuffer.Remove(packet.ConnectionId, out var _);
                        ConnectionWriteBuffer.Remove(packet.ConnectionId, out var _);
                        await Client.SendDisconnected(stream, packet.ConnectionId);
                    } else {
                        await Client.SendError(stream, DProxyError.INVALID_CONNECTION);
                    }


                    break;
                }

                case DProxyPacketType.DATA: {
                    var packet = await Client.ReadData(stream, header);

                    if (Connections.TryGetValue(packet.ConnectionId, out var socket)) {
                        try {
                            // Send the data to the TCP endpoint.
                            Logger.LogTrace("Sending {Bytes} bytes of data to {RemoteEndPoint}...", packet.Data.Length, socket.RemoteEndPoint);
                            await socket.SendAsync(packet.Data, CancellationToken.None);
                        } catch (Exception e) when (e is SocketException or IOException or InvalidOperationException) {
                            Logger.LogError(e, "Failed to relay data to the TCP endpoint.");
                            await Client.SendError(stream, DProxyError.CONNECTION_CLOSED);
                        }
                    } else {
                        await Client.SendError(stream, DProxyError.INVALID_CONNECTION);
                    }

                    break;
                }

                case DProxyPacketType.ENCRYPTED_DATA: {
                    var packet = await Client.ReadEncryptedData(stream, header);

                    if (Connections.TryGetValue(packet.ConnectionId, out var socket)) {
                        try {
                            var buffer = ConnectionWriteBuffer[packet.ConnectionId];

                            // Decrypt the data with the shared secret.
                            Logger.LogTrace("Decrypting {Bytes} bytes of data...", packet.Ciphertext.Length);
                            var cipher = new AesGcm(cek, 16);
                            cipher.Decrypt(
                                packet.IV,
                                packet.Ciphertext,
                                packet.AuthenticationTag,
                                buffer.AsSpan(0, packet.Ciphertext.Length)
                            );

                            // Send the data to the TCP endpoint.
                            Logger.LogTrace("Sending {Bytes} bytes of data to {RemoteEndPoint}...", packet.Ciphertext.Length, socket.RemoteEndPoint);
                            await socket.SendAsync(buffer.AsMemory(0, packet.Ciphertext.Length), CancellationToken.None);
                        } catch (AuthenticationTagMismatchException e) {
                            Logger.LogError(e, "Failed to decrypt data from the DProxy Server.");
                            await Client.SendError(stream, DProxyError.DECRYPT_FAILED);

                            throw new SocketException((int)SocketError.ConnectionReset);
                        } catch (Exception e) when (e is SocketException or IOException or InvalidOperationException) {
                            Logger.LogError(e, "Failed to relay data to the TCP endpoint.");
                            await Client.SendError(stream, DProxyError.CONNECTION_CLOSED);
                        }
                    } else {
                        await Client.SendError(stream, DProxyError.INVALID_CONNECTION);
                    }

                    break;
                }

                case DProxyPacketType.HEARTBEAT: {
                    var packet = await Client.ReadHeartbeat(stream, header);
                    Logger.LogTrace("Received a heartbeat from the server: {Timestamp}.", packet.Timestamp);

                    await Client.SendHeartbeatResponse(stream, packet.Timestamp, GetCurrentTimestamp());
                    break;
                }

                case DProxyPacketType.HEARTBEAT_RESPONSE: {
                    var packet = await Client.ReadHeartbeatResponse(stream, header);
                    Logger.LogTrace("Received a heartbeat response from the server: {Latency}.", packet.TimestampReceiver - packet.TimestampSender);
                    break;
                }

                case DProxyPacketType.ERROR: {
                    var packet = await Client.ReadError(stream, header);
                    Logger.LogError("Received an error response from the server: {Message}.", packet.Message);
                    break;
                }

                default:
                    Logger.LogWarning("Received an invalid packet type: {Type}.", header.Type);
                    break;
            }
        }

        private static ulong GetCurrentTimestamp()
        {
            return (ulong)new DateTimeOffset(DateTime.UtcNow).ToUnixTimeMilliseconds();
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
        private static async Task<bool> StartSocket(string serverHost, ECDiffieHellman serverKey, ECDiffieHellman clientKey)
        {
            using var _ = Logger.BeginScope(nameof(StartSocket));

            var socket = new TcpClient();

            foreach (var connection in Connections) {
                Logger.LogInformation("Closing connection {ConnectionId}...", connection.Key);
                connection.Value.Close();
            }

            Connections.Clear();
            ConnectionTasks.Clear();
            ConnectionReadBuffer.Clear();
            ConnectionWriteBuffer.Clear();

            try {
                // Establish a connection with the server.
                await socket.ConnectAsync(serverHost, 8081);
                socket.NoDelay = true;
                socket.SendBufferSize = 2 << 15;
                socket.ReceiveBufferSize = 2 << 15;
                var stream = socket.GetStream();

                // Derive the shared secret and the CEK.
                var sharedSecret = clientKey.DeriveRawSecretAgreement(serverKey.PublicKey);
                var cek          = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32);
                Logger.LogDebug("Shared secret: {SharedSecret}", Convert.ToHexString(sharedSecret));
                Logger.LogDebug("CEK: {CEK}", Convert.ToHexString(cek));

                // Start the handshake
                // Send the public key to the server.
                await Client.StartHandshake(stream, clientKey);

                // Process the response from the server.
                var handshakeResponseHeader = await Client.GetPacketHeader(stream, TimeSpan.FromSeconds(30));
                if (!Client.ValidateHeader(handshakeResponseHeader, DProxyPacketType.HANDSHAKE_RESPONSE)) {
                    return false;
                }

                // Fetch the iv, cipher text and authentication tag from the server.
                var handshakeResponse = await Client.ReadHandshakeResponse(stream, handshakeResponseHeader);
                Logger.LogDebug("IV: {IV}", Convert.ToHexString(handshakeResponse.IV));
                Logger.LogDebug("Cipher Text: {CipherText}", Convert.ToHexString(handshakeResponse.Ciphertext));
                Logger.LogDebug("Authentication Tag: {AuthenticationTag}", Convert.ToHexString(handshakeResponse.AuthenticationTag));

                // Decrypt the cipher text with the shared secret.
                var cipher    = new AesGcm(cek, 16);
                var plainText = new byte[handshakeResponse.Ciphertext.Length];
                cipher.Decrypt(handshakeResponse.IV, handshakeResponse.Ciphertext, handshakeResponse.AuthenticationTag, plainText);
                Logger.LogDebug("Plain Text: {PlainText}", Convert.ToHexString(plainText));

                // Send the plain text back to the server.
                await Client.SendHandshakeFinal(stream, plainText);

                // Check if the server accepted the message.
                var handshakeFinalizedHeader = await Client.GetPacketHeader(stream, TimeSpan.FromSeconds(30));
                if (!Client.ValidateHeader(handshakeFinalizedHeader, DProxyPacketType.HANDSHAKE_FINALIZED)) {
                    return false;
                }

                var handshakeFinalizedResponse = await Client.ReadHandshakeFinalized(stream, handshakeFinalizedHeader);
                Logger.LogDebug("User Id: {Id}", handshakeFinalizedResponse.Id);

                Logger.LogInformation("The handshake was successful.");
                while (true) {
                    var incomingHeader = await Client.GetPacketHeader(stream, Timeout.InfiniteTimeSpan);
                    await HandleServerPacket(stream, cek, incomingHeader);
                }
            } finally {
                // Close all the TCP connections when the thread is terminated.
                foreach (var connection in Connections) {
                    connection.Value.Close();

                    try {
                        if (socket.Connected && socket.GetStream().CanWrite) {
                            await Client.SendDisconnected(socket.GetStream(), connection.Key);
                        }
                    } catch (IOException e) {
                        Logger.LogError(e, "Failed to send a disconnect message to the server.");
                    } catch (SocketException e) {
                        Logger.LogError(e, "Failed to send a disconnect message to the server.");
                    }
                }

                Connections.Clear();
                ConnectionTasks.Clear();
                ConnectionReadBuffer.Clear();
                ConnectionWriteBuffer.Clear();
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
                } else {
                    serverKey = GetServerPublicKey();
                }

                if (!File.Exists(ClientPrivateKeyPath)) {
                    clientKey = CreateClientKeyPair();

                    // Send Public Key to Key Exchange Server
                    Logger.LogInformation("Sending client's public key to Key Exchange Server...");
                    await KeyServer.SendClientPublicKeyToExchangeServer(
                        clientKey,
                        (await File.ReadAllTextAsync(ClientTokenPath)).Trim()
                    );
                } else {
                    clientKey = GetClientKeyPair();
                }

                // Retry the connection if the server closed it prematurely.
                while (true) {
                    try {
                        if (!await StartSocket(ServerAddress, serverKey, clientKey)) {
                            // Stop retrying if the server rejected the message.
                            break;
                        }
                    } catch (Exception e) when (e is SocketException or IOException or AuthenticationTagMismatchException) {
                        Logger.LogError(e, "Failed to connect to the DProxy Server.");

                        await Task.Delay(5000);
                    }
                }
            } catch (Exception e) {
                Logger.LogError(e, "An unhandled exception occurred.");
            }
        }
    }
}