using Microsoft.IdentityModel.JsonWebTokens;
using System;
using System.Buffers.Binary;
using System.ComponentModel;
using System.IO;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace DProxyClient
{
    internal class Program
    {
        static readonly string serverPublicKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DProxy", "ServerPublicKey.pem");
        static readonly string clientPrivateKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DProxy", "ClientPrivateKey.pem");
        static readonly string clientPublicKeyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DProxy", "ClientPublicKey.pem");
        static readonly string clientTokenPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DProxy", "Token");

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

        static byte[] SerializePacket(DProxyHeader header, byte[] data)
        {
            var buffer = new byte[5 + data.Length];
            buffer[0] = header.Version;
            buffer[1] = (byte)header.Type;
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), header.Length);
            buffer[4] = (byte)header.ErrorCode;

            data.CopyTo(buffer.AsSpan(5, data.Length));

            return buffer;
        }

        static async Task StartHandshake(NetworkStream stream, ECDiffieHellman clientKey)
        {
            var clientPublicKey = clientKey.PublicKey.ExportSubjectPublicKeyInfo();
            var packet = new DProxyHandshakeInit(clientPublicKey);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0, 2), (ushort)packet.DERPublicKey.Length);
            packet.DERPublicKey.CopyTo(buffer.AsSpan(2, packet.DERPublicKey.Length));

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        static async Task<DProxyHeader> GetPacketHeader(NetworkStream stream, bool wait = true)
        {
            if (wait) {
                Socket.Select(new List<Socket>() { stream.Socket }, new List<Socket>(), new List<Socket>(), -1);
            }

            if (!stream.Socket.Connected || !stream.DataAvailable) {
                throw new SocketException((int)SocketError.NotConnected);
            }

            var headerBuffer = new byte[5];
            await stream.ReadExactlyAsync(headerBuffer, CancellationToken.None);

            return new DProxyHeader(headerBuffer[0], (DProxyPacketType)headerBuffer[1], BinaryPrimitives.ReadUInt16BigEndian(headerBuffer.AsSpan(2, 2)), (DProxyError)headerBuffer[4]);
        }

        static async Task<DProxyHandshakeResponse> ReadHandshakeResponse(NetworkStream stream, DProxyHeader header)
        {
            var iv = new byte[12];
            await stream.ReadExactlyAsync(iv, CancellationToken.None);

            var ciphertextLengthBuffer = new byte[2];
            await stream.ReadExactlyAsync(ciphertextLengthBuffer, CancellationToken.None);
            var ciphertextLength = BinaryPrimitives.ReadUInt16BigEndian(ciphertextLengthBuffer);

            var ciphertext = new byte[ciphertextLength];
            await stream.ReadExactlyAsync(ciphertext, CancellationToken.None);

            var authenticationTag = new byte[16];
            await stream.ReadExactlyAsync(authenticationTag, CancellationToken.None);

            return new DProxyHandshakeResponse(iv, ciphertext, authenticationTag);
        }

        static async Task SendHandshakeFinal(NetworkStream stream, byte[] plaintext)
        {
            var packet = new DProxyHandshakeFinal(plaintext);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0, 2), (ushort)packet.Plaintext.Length);
            packet.Plaintext.CopyTo(buffer.AsSpan(2, packet.Plaintext.Length));

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        static async Task<DProxyConnect> ReadConnect(NetworkStream stream, DProxyHeader header)
        {
            var connectionIdBuffer = new byte[4];
            await stream.ReadExactlyAsync(connectionIdBuffer, CancellationToken.None);
            var connectionId = BinaryPrimitives.ReadUInt32BigEndian(connectionIdBuffer);

            var destinationLengthBuffer = new byte[2];
            await stream.ReadExactlyAsync(destinationLengthBuffer, CancellationToken.None);
            var destinationLength = BinaryPrimitives.ReadUInt16BigEndian(destinationLengthBuffer);

            var destination = new byte[destinationLength];
            await stream.ReadExactlyAsync(destination, CancellationToken.None);

            var portBuffer = new byte[2];
            await stream.ReadExactlyAsync(portBuffer, CancellationToken.None);
            var port = BinaryPrimitives.ReadUInt16BigEndian(portBuffer);

            return new DProxyConnect(connectionId, Encoding.UTF8.GetString(destination), port);
        }

        static async Task SendConnected(NetworkStream stream, uint connectionId)
        {
            var packet = new DProxyConnected(connectionId);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), packet.ConnectionId);

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        static async Task<DProxyDisconnect> ReadDisconnect(NetworkStream stream, DProxyHeader header)
        {
            var connectionIdBuffer = new byte[4];
            await stream.ReadExactlyAsync(connectionIdBuffer, CancellationToken.None);
            var connectionId = BinaryPrimitives.ReadUInt32BigEndian(connectionIdBuffer);

            return new DProxyDisconnect(connectionId);
        }

        static async Task SendDisconnected(NetworkStream stream, uint connectionId)
        {
            var packet = new DProxyDisconnected(connectionId);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), packet.ConnectionId);

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        static async Task<DProxyData> ReadData(NetworkStream stream, DProxyHeader header)
        {
            var connectionIdBuffer = new byte[4];
            await stream.ReadExactlyAsync(connectionIdBuffer, CancellationToken.None);
            var connectionId = BinaryPrimitives.ReadUInt32BigEndian(connectionIdBuffer);

            var iv = new byte[12];
            await stream.ReadExactlyAsync(iv, CancellationToken.None);

            var ciphertextLengthBuffer = new byte[2];
            await stream.ReadExactlyAsync(ciphertextLengthBuffer, CancellationToken.None);
            var ciphertextLength = BinaryPrimitives.ReadUInt16BigEndian(ciphertextLengthBuffer);

            var ciphertext = new byte[ciphertextLength];
            await stream.ReadExactlyAsync(ciphertext, CancellationToken.None);

            var authenticationTag = new byte[16];
            await stream.ReadExactlyAsync(authenticationTag, CancellationToken.None);

            return new DProxyData(connectionId, iv, ciphertext, authenticationTag);
        }

        static async Task SendData(NetworkStream stream, uint connectionId, byte[] iv, byte[] ciphertext, byte[] authenticationTag)
        {
            var packet = new DProxyData(connectionId, iv, ciphertext, authenticationTag);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), packet.ConnectionId);
            iv.CopyTo(buffer.AsSpan(4, 12));
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(16, 2), (ushort)packet.Ciphertext.Length);
            ciphertext.CopyTo(buffer.AsSpan(18, packet.Ciphertext.Length));
            authenticationTag.CopyTo(buffer.AsSpan(18 + packet.Ciphertext.Length, 16));

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        static async Task<DProxyHeartbeat> ReadHeartbeat(NetworkStream stream, DProxyHeader header)
        {
            var timestampBuffer = new byte[8];
            await stream.ReadExactlyAsync(timestampBuffer, CancellationToken.None);
            var timestamp = BinaryPrimitives.ReadUInt64BigEndian(timestampBuffer);

            return new DProxyHeartbeat(timestamp);
        }

        static async Task SendHeartbeat(NetworkStream stream, ulong timestamp)
        {
            var packet = new DProxyHeartbeat(timestamp);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(0, 8), packet.Timestamp);

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }
        static async Task<DProxyHeartbeatResponse> ReadHeartbeatResponse(NetworkStream stream, DProxyHeader header)
        {
            var timestampBuffer = new byte[8];
            await stream.ReadExactlyAsync(timestampBuffer, CancellationToken.None);
            var timestamp = BinaryPrimitives.ReadUInt64BigEndian(timestampBuffer);

            return new DProxyHeartbeatResponse(timestamp);
        }

        static async Task SendHeartbeatResponse(NetworkStream stream, ulong timestamp)
        {
            var packet = new DProxyHeartbeatResponse(timestamp);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(0, 8), packet.Timestamp);

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        static async Task SendError(NetworkStream stream, DProxyError errorCode, string message = "")
        {
            var packet = new DProxyErrorPacket(errorCode, message);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0, 2), (ushort)message.Length);
            Encoding.UTF8.GetBytes(message).CopyTo(buffer.AsSpan(2, message.Length));

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        static bool ValidateHeader(DProxyHeader header, DProxyPacketType expectedType)
        {
            if (header.Type != expectedType) {
                Console.Error.WriteLine($"Received an invalid packet type: {header.Type}.");
                return false;
            }

            if (header.ErrorCode != DProxyError.NO_ERROR) {
                Console.Error.WriteLine($"Received an error response: {header.ErrorCode}.");
                return false;
            }

            return true;
        }

        static async Task ReadSockets(AesGcm cipher, NetworkStream stream)
        {
            var buffer = new byte[2 << 14];

            try {
                // Read the data from the TCP endpoints and relay it to the server.
                foreach (var connection in Connections) {
                    var connectionId = connection.Key;
                    var client = connection.Value;

                    while (client.Available > 0) {
                        //Console.WriteLine($"Reading {client.Available} from {client.Client.RemoteEndPoint}...");
                        var bytesRead = await client.GetStream().ReadAsync(buffer, CancellationToken.None);
                        if (bytesRead == 0) {
                            break;
                        }

                        // Encrypt the data with the shared secret.
                        var iv = new byte[12];
                        RandomNumberGenerator.Fill(iv);
                        var cipherText = new byte[bytesRead];
                        var authTag = new byte[16];
                        cipher.Encrypt(iv, buffer.AsSpan(0, bytesRead), cipherText, authTag);

                        // Send the data to the server.
                        //Console.WriteLine($"Sending {bytesRead} bytes of data to the server.");
                        await SendData(stream, connectionId, iv, cipherText, authTag);
                    }
                }
            } catch (Exception e) {
                Console.Error.WriteLine($"Failed to read data from the TCP endpoints: {e.GetType().Name} - {e.Message}");
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
                await StartHandshake(stream, clientKey);

                // Process the response from the server.
                var handshakeResponseHeader = await GetPacketHeader(stream);
                if (!ValidateHeader(handshakeResponseHeader, DProxyPacketType.HANDSHAKE_RESPONSE)) {
                    return false;
                }

                // Fetch the iv, cipher text and authentication tag from the server.
                var handshakeResponse = await ReadHandshakeResponse(stream, handshakeResponseHeader);
                Console.WriteLine($"IV: {BitConverter.ToString(handshakeResponse.IV).Replace("-", "")}");
                Console.WriteLine($"Cipher Text: {BitConverter.ToString(handshakeResponse.Ciphertext).Replace("-", "")}");
                Console.WriteLine($"Authentication Tag: {BitConverter.ToString(handshakeResponse.AuthenticationTag).Replace("-", "")}");

                // Decrypt the cipher text with the shared secret.
                var cipher = new AesGcm(cek, 16);
                var plainText = new byte[handshakeResponse.Ciphertext.Length];
                cipher.Decrypt(handshakeResponse.IV, handshakeResponse.Ciphertext, handshakeResponse.AuthenticationTag, plainText);
                Console.WriteLine($"Plain Text: {BitConverter.ToString(plainText).Replace("-", "")}");

                // Send the plain text back to the server.
                await SendHandshakeFinal(stream, plainText);

                // Check if the server accepted the message.
                var handshakeResultHeader = await GetPacketHeader(stream);
                if (!ValidateHeader(handshakeResultHeader, DProxyPacketType.HANDSHAKE_FINALIZED)) {
                    return false;
                }

                Console.WriteLine("The handshake was successful.");

                var buffer = new byte[2 << 14];
                while (true) {
                    if (!stream.Socket.Connected) {
                        throw new SocketException((int)SocketError.NotConnected);
                    }

                    var waitList = new List<Socket>(Connections.Count + 1) {
                        stream.Socket
                    };

                    for (var i = 0; i < Connections.Count; i++) {
                        if (!Connections.Values.ElementAt(i).Connected) {
                            continue;
                        }

                        waitList.Add(Connections.Values.ElementAt(i).GetStream().Socket);
                    }

                    // Wait for data to be available on any of the TCP endpoints.
                    Socket.Select(waitList, new List<Socket>(), new List<Socket>(), -1);

                    // Read the data from the TCP endpoints and relay it to the server.
                    await ReadSockets(cipher, stream);

                    if (stream.Socket.Available == 0) {
                        if (waitList.Count == 1) {
                            await SendHeartbeat(stream, (ulong)new DateTimeOffset(DateTime.UtcNow).ToUnixTimeMilliseconds());
                        }

                        continue;
                    }

                    var incomingHeader = await GetPacketHeader(stream, false);
                    switch (incomingHeader.Type) {
                        case DProxyPacketType.CONNECT: {
                            var connect = await ReadConnect(stream, incomingHeader);
                            Console.WriteLine($"Connecting to {connect.Destination}:{connect.Port}...");

                            if (Connections.ContainsKey(connect.ConnectionId)) {
                                await SendError(stream, DProxyError.INVALID_CONNECTION);
                                continue;
                            }

                            try {
                                var client = new TcpClient();
                                await client.ConnectAsync(connect.Destination, connect.Port);

                                Connections[connect.ConnectionId] = client;

                                await SendConnected(stream, connect.ConnectionId);
                            } catch (SocketException e) {
                                Console.Error.WriteLine($"Failed to connect to {connect.Destination}:{connect.Port}: {e.GetType().Name} - {e.Message}");
                                await SendError(stream, DProxyError.CONNECTION_FAILED);
                            }

                            break;
                        }

                        case DProxyPacketType.DISCONNECT: {
                            var disconnect = await ReadDisconnect(stream, incomingHeader);

                            if (Connections.TryGetValue(disconnect.ConnectionId, out var client)) {
                                Console.WriteLine($"Disconnecting from {client.Client.RemoteEndPoint}...");
                                client.Close();
                                Connections.Remove(disconnect.ConnectionId);
                                await SendDisconnected(stream, disconnect.ConnectionId);
                            } else {
                                await SendError(stream, DProxyError.INVALID_CONNECTION);
                            }

                            break;
                        }

                        case DProxyPacketType.DATA: {
                            var data = await ReadData(stream, incomingHeader);

                            if (Connections.TryGetValue(data.ConnectionId, out var client)) {
                                try {
                                    // Decrypt the data with the shared secret.
                                    cipher.Decrypt(data.IV, data.Ciphertext, data.AuthenticationTag, new Span<byte>(buffer, 0, data.Ciphertext.Length));

                                    // Send the data to the TCP endpoint.
                                    await client.GetStream().WriteAsync(buffer.AsMemory(0, data.Ciphertext.Length));
                                } catch (SocketException e) {
                                    Console.Error.WriteLine($"Failed to relay data to the TCP endpoint: {e.GetType().Name} - {e.Message}");
                                    await SendError(stream, DProxyError.CONNECTION_FAILED);
                                } catch (IOException e) {
                                    Console.Error.WriteLine($"Failed to relay data to the TCP endpoint: {e.GetType().Name} - {e.Message}");
                                    await SendError(stream, DProxyError.CONNECTION_CLOSED);
                                }
                            } else {
                                await SendError(stream, DProxyError.INVALID_CONNECTION);
                            }

                            break;
                        }

                        case DProxyPacketType.HEARTBEAT: {
                            var heartbeat = await ReadHeartbeat(stream, incomingHeader);
                            // Console.WriteLine($"Received a heartbeat from the server: {heartbeat.Timestamp}.");
                            await SendHeartbeatResponse(stream, (ulong)new DateTimeOffset(DateTime.UtcNow).ToUnixTimeMilliseconds());
                            break;
                        }

                        case DProxyPacketType.HANDSHAKE_RESPONSE:
                            var heartbeatResponse = await ReadHeartbeatResponse(stream, incomingHeader);
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
                            await SendDisconnected(socket.GetStream(), connection.Key);
                        }
                    } catch (IOException e) {
                        Console.Error.WriteLine($"Failed to send a disconnect message to the server: {e.GetType().Name} - {e.Message}");
                    } catch (SocketException e) {
                        Console.Error.WriteLine($"Failed to send a disconnect message to the server: {e.GetType().Name} - {e.Message}");
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

                if (!File.Exists(serverPublicKeyPath)) {
                    Console.WriteLine("Fetching server's public key from Key Exchange Server...");
                    serverKey = await KeyServer.GetServerPublicKeyFromExchangeServer();

                    // Save the server's public key to the file system.
                    File.WriteAllText(serverPublicKeyPath, serverKey.ExportSubjectPublicKeyInfoPem());
                } else {
                    serverKey = GetServerPublicKey();
                }

                if (!File.Exists(clientPrivateKeyPath)) {
                    clientKey = CreateClientKeyPair();

                    // Send Public Key to Key Exchange Server
                    Console.WriteLine("Sending client's public key to Key Exchange Server...");
                    await KeyServer.SendClientPublicKeyToExchangeServer(clientKey, File.ReadAllText(clientTokenPath).Trim());
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
                        Console.Error.WriteLine($"Failed to connect to the DProxy Server: {e.GetType().Name} - {e.Message}");

                        await Task.Delay(5000);
                    } catch (IOException e) {
                        Console.Error.WriteLine($"Failed to send data to the DProxy Server: {e.GetType().Name} - {e.Message}");

                        await Task.Delay(5000);
                    }
                }
            } catch (Exception e) {
                Console.Error.WriteLine($"{e.GetType().Name}: {e.Message}");
            }
        }
    }
}
