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

using System.Net.Sockets;
using System.Security.Cryptography;

namespace DProxyClient
{
    internal class Program
    {
        static readonly string configPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DProxy");
        static readonly string serverPublicKeyPath = Path.Combine(configPath, "ServerPublicKey.pem");
        static readonly string clientPrivateKeyPath = Path.Combine(configPath, "ClientPrivateKey.pem");
        static readonly string clientPublicKeyPath = Path.Combine(configPath, "ClientPublicKey.pem");
        static readonly string clientTokenPath = Path.Combine(configPath, "Token");

        /**
         * Get the server's public key from the file system.
         * 
         * @return The server's public key.
         */
        static ECDiffieHellman GetServerPublicKey()
        {
            var serverPublicKey = File.ReadAllText(serverPublicKeyPath);
            var serverKey = ECDiffieHellman.Create();
            serverKey.ImportFromPem(serverPublicKey);

            return serverKey;
        }

        /**
         * Get the client's key pair from the file system.
         * 
         * @return The client's key pair.
         */
        static ECDiffieHellman GetClientKeyPair()
        {
            var clientPrivateKey = File.ReadAllText(clientPrivateKeyPath);
            var clientKey = ECDiffieHellman.Create();
            clientKey.ImportFromPem(clientPrivateKey);

            return clientKey;
        }

        /**
         * Create a new client key pair and save it to the file system.
         * 
         * @return The client's key pair.
         */
        static ECDiffieHellman CreateClientKeyPair()
        {
            var clientKey = ECDiffieHellman.Create(ECCurve.CreateFromFriendlyName("secp384r1"));
            var clientPublicKey = clientKey.ExportSubjectPublicKeyInfoPem();
            var clientPrivateKey = clientKey.ExportPkcs8PrivateKeyPem();

            File.WriteAllText(clientPrivateKeyPath, clientPrivateKey);
            File.WriteAllText(clientPublicKeyPath, clientPublicKey);

            return clientKey;
        }

        /**
         * ConnectionID -> TCP Connection Map
         */
        static readonly Dictionary<uint, TcpClient> Connections = [];
        
        static byte[] readBuffer = new byte[2 << 14];
        
        static byte[] writeBuffer = new byte[2 << 14];

        static async Task ReadSockets(AesGcm cipher, NetworkStream stream)
        {
            try {
                // Read the data from the TCP endpoints and relay it to the server.
                foreach (var (connectionId, client) in Connections) {
                    while (client.Available > 0) {
                        //Console.WriteLine($"Reading {client.Available} from {client.Client.RemoteEndPoint}...");
                        var bytesRead = await client.GetStream().ReadAsync(readBuffer, CancellationToken.None);
                        if (bytesRead == 0) {
                            break;
                        }

                        // Encrypt the data with the shared secret.
                        var iv = new byte[12];
                        RandomNumberGenerator.Fill(iv);
                        var cipherText = new byte[bytesRead];
                        var authTag = new byte[16];
                        cipher.Encrypt(iv, readBuffer.AsSpan(0, bytesRead), cipherText, authTag);

                        // Send the data to the server.
                        //Console.WriteLine($"Sending {bytesRead} bytes of data to the server.");
                        await Client.SendData(stream, connectionId, iv, cipherText, authTag);
                    }
                }
            } catch (Exception e) {
                Console.Error.WriteLine($"Failed to read data from the TCP endpoints: {e.GetType().Name} - {e.Message}\n{e.StackTrace}");
            }
        }

        /**
         * Start the Socket connection with the server.
         * 
         * @param serverKey The server's public key.
         * @param clientKey The client's key pair.
         * @return Whether the connection was successful.
         */
        static async Task<bool> StartSocket(string serverHost, ECDiffieHellman serverKey, ECDiffieHellman clientKey)
        {
            var socket = new TcpClient();

            foreach (var connection in Connections) {
                Console.WriteLine($"Closing connection {connection.Key}...");
                connection.Value.Close();
            }

            Connections.Clear();

            try {
                // Establish a connection with the server.
                await socket.ConnectAsync(serverHost, 8081);
                var stream = socket.GetStream();

                // Derive the shared secret and the CEK.
                var sharedSecret = clientKey.DeriveRawSecretAgreement(serverKey.PublicKey);
                var cek = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, null, null);
                Console.WriteLine($"Shared secret: {BitConverter.ToString(sharedSecret).Replace("-", "")}");
                Console.WriteLine($"CEK: {BitConverter.ToString(cek).Replace("-", "")}");

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
                Console.WriteLine($"IV: {BitConverter.ToString(handshakeResponse.IV).Replace("-", "")}");
                Console.WriteLine($"Cipher Text: {BitConverter.ToString(handshakeResponse.Ciphertext).Replace("-", "")}");
                Console.WriteLine($"Authentication Tag: {BitConverter.ToString(handshakeResponse.AuthenticationTag).Replace("-", "")}");

                // Decrypt the cipher text with the shared secret.
                var cipher = new AesGcm(cek, 16);
                var plainText = new byte[handshakeResponse.Ciphertext.Length];
                cipher.Decrypt(handshakeResponse.IV, handshakeResponse.Ciphertext, handshakeResponse.AuthenticationTag, plainText);
                Console.WriteLine($"Plain Text: {BitConverter.ToString(plainText).Replace("-", "")}");

                // Send the plain text back to the server.
                await Client.SendHandshakeFinal(stream, plainText);

                // Check if the server accepted the message.
                var handshakeResultHeader = await Client.GetPacketHeader(stream);
                if (!Client.ValidateHeader(handshakeResultHeader, DProxyPacketType.HANDSHAKE_FINALIZED)) {
                    return false;
                }

                Console.WriteLine("The handshake was successful.");
                
                while (true) {
                    if (!stream.Socket.Connected) {
                        throw new SocketException((int)SocketError.NotConnected);
                    }

                    var waitList = new List<Socket>(Connections.Count + 1) {
                        stream.Socket
                    };
                    
                    waitList.AddRange(from connection in Connections.Select((t, i) => Connections.Values.ElementAt(i)) where connection.Connected select connection.GetStream().Socket);

                    // Wait for data to be available on any of the TCP endpoints.
                    Socket.Select(waitList, null, null, TimeSpan.FromSeconds(30));

                    // Read the data from the TCP endpoints and relay it to the server.
                    await ReadSockets(cipher, stream);

                    if (stream.Socket.Available == 0) {
                        if (waitList.Count == 1) {
                            await Client.SendHeartbeat(stream, (ulong)new DateTimeOffset(DateTime.UtcNow).ToUnixTimeMilliseconds());
                        }

                        continue;
                    }

                    var incomingHeader = await Client.GetPacketHeader(stream, false);
                    switch (incomingHeader.Type) {
                        case DProxyPacketType.CONNECT: {
                            var connect = await Client.ReadConnect(stream, incomingHeader);
                            Console.WriteLine($"Connecting to {connect.Destination}:{connect.Port}...");

                            if (Connections.ContainsKey(connect.ConnectionId)) {
                                await Client.SendError(stream, DProxyError.INVALID_CONNECTION);
                                continue;
                            }

                            try {
                                var client = new TcpClient();
                                await client.ConnectAsync(connect.Destination, connect.Port);

                                Connections[connect.ConnectionId] = client;

                                await Client.SendConnected(stream, connect.ConnectionId);
                            } catch (SocketException e) {
                                Console.Error.WriteLine($"Failed to connect to {connect.Destination}:{connect.Port}: {e.GetType().Name} - {e.Message}\n{e.StackTrace}");
                                await Client.SendError(stream, DProxyError.CONNECTION_FAILED);
                            }

                            break;
                        }

                        case DProxyPacketType.DISCONNECT: {
                            var disconnect = await Client.ReadDisconnect(stream, incomingHeader);

                            if (Connections.TryGetValue(disconnect.ConnectionId, out var client)) {
                                try {
                                    Console.WriteLine($"Disconnecting from {client.Client.RemoteEndPoint}...");
                                    client.Close();
                                } catch (SocketException) {
                                    //
                                }

                                Connections.Remove(disconnect.ConnectionId);
                                await Client.SendDisconnected(stream, disconnect.ConnectionId);
                            } else {
                                await Client.SendError(stream, DProxyError.INVALID_CONNECTION);
                            }

                            break;
                        }

                        case DProxyPacketType.DATA: {
                            var data = await Client.ReadData(stream, incomingHeader);

                            if (Connections.TryGetValue(data.ConnectionId, out var client)) {
                                try {
                                    // Decrypt the data with the shared secret.
                                    cipher.Decrypt(data.IV, data.Ciphertext, data.AuthenticationTag, new Span<byte>(writeBuffer, 0, data.Ciphertext.Length));

                                    // Send the data to the TCP endpoint.
                                    await client.GetStream().WriteAsync(writeBuffer.AsMemory(0, data.Ciphertext.Length));
                                } catch (AuthenticationTagMismatchException e) {
                                    Console.Error.WriteLine($"Failed to decrypt data from the DProxy Server: {e.GetType().Name} - {e.Message}\n{e.StackTrace}");
                                    throw new SocketException((int)SocketError.ConnectionReset);
                                } catch (SocketException e) {
                                    Console.Error.WriteLine($"Failed to relay data to the TCP endpoint: {e.GetType().Name} - {e.Message}\n{e.StackTrace}");
                                    await Client.SendError(stream, DProxyError.CONNECTION_FAILED);
                                } catch (IOException e) {
                                    Console.Error.WriteLine($"Failed to relay data to the TCP endpoint: {e.GetType().Name} - {e.Message}\n{e.StackTrace}");
                                    await Client.SendError(stream, DProxyError.CONNECTION_CLOSED);
                                }
                            } else {
                                await Client.SendError(stream, DProxyError.INVALID_CONNECTION);
                            }

                            break;
                        }

                        case DProxyPacketType.HEARTBEAT: {
                            var heartbeat = await Client.ReadHeartbeat(stream, incomingHeader);
                            // Console.WriteLine($"Received a heartbeat from the server: {heartbeat.Timestamp}.");
                            await Client.SendHeartbeatResponse(stream, (ulong)new DateTimeOffset(DateTime.UtcNow).ToUnixTimeMilliseconds());
                            break;
                        }

                        case DProxyPacketType.HEARTBEAT_RESPONSE:
                            var heartbeatResponse = await Client.ReadHeartbeatResponse(stream, incomingHeader);
                            break;

                        default:
                            Console.Error.WriteLine($"Received an invalid packet type: {incomingHeader.Type}.");
                            continue;
                    }
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
                        Console.Error.WriteLine($"Failed to send a disconnect message to the server: {e.GetType().Name} - {e.Message}\n{e.StackTrace}");
                    } catch (SocketException e) {
                        Console.Error.WriteLine($"Failed to send a disconnect message to the server: {e.GetType().Name} - {e.Message}\n{e.StackTrace}");
                    }
                }

                Connections.Clear();
                socket.Close();
            }
        }

        private static async Task Main(string[] args)
        {
            try {
                ECDiffieHellman serverKey;
                ECDiffieHellman clientKey;

                if (!File.Exists(configPath)) {
                    Directory.CreateDirectory(configPath);
                }

                if (!File.Exists(serverPublicKeyPath)) {
                    Console.WriteLine("Fetching server's public key from Key Exchange Server...");
                    serverKey = await KeyServer.GetServerPublicKeyFromExchangeServer();

                    // Save the server's public key to the file system.
                    await File.WriteAllTextAsync(serverPublicKeyPath, serverKey.ExportSubjectPublicKeyInfoPem());
                } else {
                    serverKey = GetServerPublicKey();
                }

                if (!File.Exists(clientPrivateKeyPath)) {
                    clientKey = CreateClientKeyPair();

                    // Send Public Key to Key Exchange Server
                    Console.WriteLine("Sending client's public key to Key Exchange Server...");
                    await KeyServer.SendClientPublicKeyToExchangeServer(clientKey, (await File.ReadAllTextAsync(clientTokenPath)).Trim());
                } else {
                    clientKey = GetClientKeyPair();
                }

                // Retry the connection if the server closed it prematurely.
                while (true) {
                    try {
                        if (!await StartSocket("localhost", serverKey, clientKey)) {
                            // Stop retrying if the server rejected the message.
                            break;
                        }
                    } catch (SocketException e) {
                        Console.Error.WriteLine($"Failed to connect to the DProxy Server: {e.GetType().Name} - {e.Message}\n{e.StackTrace}");

                        await Task.Delay(5000);
                    } catch (IOException e) {
                        Console.Error.WriteLine($"Failed to send data to the DProxy Server: {e.GetType().Name} - {e.Message}\n{e.StackTrace}");

                        await Task.Delay(5000);
                    }
                }
            } catch (Exception e) {
                Console.Error.WriteLine($"{e.GetType().Name}: {e.Message}\n{e.StackTrace}");
            }
        }
    }
}
