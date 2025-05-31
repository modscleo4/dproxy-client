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

using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace DProxyClient
{
    public static class Client
    {
        private static byte[] SerializePacket(DProxyHeader header, byte[] data)
        {
            var buffer = new byte[5 + data.Length];
            buffer[0] = header.Version;
            buffer[1] = (byte)header.Type;
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(2, 2), header.Length);
            buffer[4] = (byte)header.ErrorCode;

            data.CopyTo(buffer.AsSpan(5, data.Length));

            return buffer;
        }

        public static async Task StartHandshake(NetworkStream stream, ECDiffieHellman clientKey)
        {
            var clientPublicKey = clientKey.PublicKey.ExportSubjectPublicKeyInfo();
            var packet          = new DProxyHandshakeInit(clientPublicKey);
            var buffer          = new byte[packet.Length];
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0, 2), (ushort)packet.DERPublicKey.Length);
            packet.DERPublicKey.CopyTo(buffer.AsSpan(2, packet.DERPublicKey.Length));

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        public static async Task<DProxyHeader> GetPacketHeader(NetworkStream stream, TimeSpan timeout)
        {
            // Wait for data to be available on the TCP endpoint.
            if (!stream.Socket.Poll(timeout, SelectMode.SelectRead)) {
                throw new SocketException((int)SocketError.TimedOut);
            }

            if (!stream.Socket.Connected || !stream.DataAvailable) {
                throw new SocketException((int)SocketError.NotConnected);
            }

            var headerBuffer = new byte[5];
            await stream.ReadExactlyAsync(headerBuffer, CancellationToken.None);

            return new DProxyHeader(
                headerBuffer[0],
                (DProxyPacketType)headerBuffer[1],
                BinaryPrimitives.ReadUInt16BigEndian(headerBuffer.AsSpan(2, 2)),
                (DProxyError)headerBuffer[4]
            );
        }

        public static async Task<DProxyHandshakeResponse> ReadHandshakeResponse(NetworkStream stream,
            DProxyHeader header)
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

        public static async Task SendHandshakeFinal(NetworkStream stream, byte[] plaintext)
        {
            var packet = new DProxyHandshakeFinal(plaintext);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0, 2), (ushort)packet.Plaintext.Length);
            packet.Plaintext.CopyTo(buffer.AsSpan(2, packet.Plaintext.Length));

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        public static async Task<DProxyConnect> ReadConnect(NetworkStream stream, DProxyHeader header)
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

        public static async Task SendConnected(NetworkStream stream, uint connectionId)
        {
            var packet = new DProxyConnected(connectionId);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), packet.ConnectionId);

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        public static async Task<DProxyDisconnect> ReadDisconnect(NetworkStream stream, DProxyHeader header)
        {
            var connectionIdBuffer = new byte[4];
            await stream.ReadExactlyAsync(connectionIdBuffer, CancellationToken.None);
            var connectionId = BinaryPrimitives.ReadUInt32BigEndian(connectionIdBuffer);

            return new DProxyDisconnect(connectionId);
        }

        public static async Task SendDisconnected(NetworkStream stream, uint connectionId)
        {
            var packet = new DProxyDisconnected(connectionId);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), packet.ConnectionId);

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        public static async Task<DProxyData> ReadData(NetworkStream stream, DProxyHeader header)
        {
            var connectionIdBuffer = new byte[4];
            await stream.ReadExactlyAsync(connectionIdBuffer, CancellationToken.None);
            var connectionId = BinaryPrimitives.ReadUInt32BigEndian(connectionIdBuffer);

            var dataLengthBuffer = new byte[2];
            await stream.ReadExactlyAsync(dataLengthBuffer, CancellationToken.None);
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(dataLengthBuffer);

            var data = new byte[dataLength];
            await stream.ReadExactlyAsync(data, CancellationToken.None);

            return new DProxyData(connectionId, data);
        }

        public static async Task SendData(NetworkStream stream, uint connectionId, byte[] data)
        {
            var packet = new DProxyData(connectionId, data);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), packet.ConnectionId);
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4, 2), (ushort)packet.Data.Length);
            data.CopyTo(buffer.AsSpan(6, packet.Data.Length));

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        public static async Task<DProxyEncryptedData> ReadEncryptedData(NetworkStream stream, DProxyHeader header)
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

            return new DProxyEncryptedData(connectionId, iv, ciphertext, authenticationTag);
        }

        public static async Task SendEncryptedData(NetworkStream stream, uint connectionId, byte[] iv, byte[] ciphertext, byte[] authenticationTag)
        {
            var packet = new DProxyEncryptedData(connectionId, iv, ciphertext, authenticationTag);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(0, 4), packet.ConnectionId);
            iv.CopyTo(buffer.AsSpan(4, 12));
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(16, 2), (ushort)packet.Ciphertext.Length);
            ciphertext.CopyTo(buffer.AsSpan(18, packet.Ciphertext.Length));
            authenticationTag.CopyTo(buffer.AsSpan(18 + packet.Ciphertext.Length, 16));

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        public static async Task<DProxyHeartbeat> ReadHeartbeat(NetworkStream stream, DProxyHeader header)
        {
            var timestampBuffer = new byte[8];
            await stream.ReadExactlyAsync(timestampBuffer, CancellationToken.None);
            var timestamp = BinaryPrimitives.ReadUInt64BigEndian(timestampBuffer);

            return new DProxyHeartbeat(timestamp);
        }

        public static async Task SendHeartbeat(NetworkStream stream, ulong timestamp)
        {
            var packet = new DProxyHeartbeat(timestamp);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(0, 8), packet.Timestamp);

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        public static async Task<DProxyHeartbeatResponse> ReadHeartbeatResponse(NetworkStream stream,
            DProxyHeader header)
        {
            var timestampBuffer = new byte[8];
            await stream.ReadExactlyAsync(timestampBuffer, CancellationToken.None);
            var timestamp = BinaryPrimitives.ReadUInt64BigEndian(timestampBuffer);

            return new DProxyHeartbeatResponse(timestamp);
        }

        public static async Task SendHeartbeatResponse(NetworkStream stream, ulong timestamp)
        {
            var packet = new DProxyHeartbeatResponse(timestamp);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(0, 8), packet.Timestamp);

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        public static async Task<DProxyErrorPacket> ReadError(NetworkStream stream, DProxyHeader header)
        {
            var messageLengthBuffer = new byte[2];
            await stream.ReadExactlyAsync(messageLengthBuffer, CancellationToken.None);
            var messageLength = BinaryPrimitives.ReadUInt16BigEndian(messageLengthBuffer);

            var message = new byte[messageLength];
            await stream.ReadExactlyAsync(message, CancellationToken.None);

            return new DProxyErrorPacket(header.ErrorCode, Encoding.UTF8.GetString(message));
        }

        public static async Task SendError(NetworkStream stream, DProxyError errorCode, string message = "")
        {
            var packet = new DProxyErrorPacket(errorCode, message);
            var buffer = new byte[packet.Length];
            BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(0, 2), (ushort)message.Length);
            Encoding.UTF8.GetBytes(message).CopyTo(buffer.AsSpan(2, message.Length));

            await stream.WriteAsync(SerializePacket(packet, buffer), CancellationToken.None);
        }

        public static bool ValidateHeader(DProxyHeader header, DProxyPacketType expectedType)
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
    }
}