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

using System.Text;

namespace DProxyClient;

public enum DProxyPacketType : byte
{
    HANDSHAKE_INIT,
    HANDSHAKE_RESPONSE,
    HANDSHAKE_FINAL,
    HANDSHAKE_FINALIZED,
    CONNECT,
    CONNECTED,
    DISCONNECT,
    DISCONNECTED,
    DATA,
    ENCRYPTED_DATA,
    HEARTBEAT,
    HEARTBEAT_RESPONSE,
    ERROR,
}

public enum DProxyError : byte
{
    NO_ERROR,
    INVALID_VERSION,
    INVALID_PACKET_TYPE,
    INVALID_PACKET_LENGTH,
    INVALID_HANDSHAKE_INFO,
    HANDSHAKE_FAILED,
    ALREADY_AUTHENTICATED,
    INVALID_DESTINATION,
    CONNECTION_FAILED,
    CONNECTION_CLOSED,
    CONNECTION_TIMEOUT,
    INVALID_CONNECTION,
    DECRYPT_FAILED,
}

public enum DProxyConnectionType : byte
{
    TCP,
    UDP,
}

[Serializable()]
public record DProxyHeader(byte Version, DProxyPacketType Type, ushort Length, DProxyError ErrorCode);

public record DProxyHandshakeInit(byte[] DERPublicKey, string Hello) : DProxyHeader(1, DProxyPacketType.HANDSHAKE_INIT, (ushort)(2 + DERPublicKey.Length + 2 + Encoding.UTF8.GetByteCount(Hello)), DProxyError.NO_ERROR);

public record DProxyHandshakeResponse(byte[] IV, byte[] Ciphertext, byte[] AuthenticationTag) : DProxyHeader(1, DProxyPacketType.HANDSHAKE_RESPONSE, (ushort)(IV.Length + 2 + Ciphertext.Length + AuthenticationTag.Length), DProxyError.NO_ERROR);

public record DProxyHandshakeFinal(byte[] Plaintext) : DProxyHeader(1, DProxyPacketType.HANDSHAKE_FINAL, (ushort)(2 + Plaintext.Length), DProxyError.NO_ERROR);

public record DProxyHandshakeFinalized(string Id) : DProxyHeader(1, DProxyPacketType.HANDSHAKE_FINALIZED, (ushort)(2 + Encoding.UTF8.GetByteCount(Id)), DProxyError.NO_ERROR);

public record DProxyConnect(uint ConnectionId, DProxyConnectionType ConnectionType, string Destination, ushort Port) : DProxyHeader(1, DProxyPacketType.CONNECT, (ushort)(4 + 1 + 2 + Encoding.UTF8.GetByteCount(Destination) + 2), DProxyError.NO_ERROR);

public record DProxyConnected(uint ConnectionId, string Endpoint, ushort Port) : DProxyHeader(1, DProxyPacketType.CONNECTED, (ushort)(4 + 2 + Encoding.UTF8.GetByteCount(Endpoint) + 2), DProxyError.NO_ERROR);

public record DProxyDisconnect(uint ConnectionId) : DProxyHeader(1, DProxyPacketType.DISCONNECT, 4, DProxyError.NO_ERROR);

public record DProxyDisconnected(uint ConnectionId, DProxyError ErrorCode = DProxyError.NO_ERROR) : DProxyHeader(1, DProxyPacketType.DISCONNECTED, 4, ErrorCode);

public record DProxyData(uint ConnectionId, byte[] Data) : DProxyHeader(1, DProxyPacketType.DATA, (ushort)(4 + 2 + Data.Length), DProxyError.NO_ERROR);

public record DProxyEncryptedData(uint ConnectionId, byte[] IV, byte[] Ciphertext, byte[] AuthenticationTag) : DProxyHeader(1, DProxyPacketType.ENCRYPTED_DATA, (ushort)(4 + IV.Length + 2 + Ciphertext.Length + AuthenticationTag.Length), DProxyError.NO_ERROR);

public record DProxyHeartbeat(ulong Timestamp) : DProxyHeader(1, DProxyPacketType.HEARTBEAT, 8, DProxyError.NO_ERROR);

public record DProxyHeartbeatResponse(ulong TimestampSender, ulong TimestampReceiver) : DProxyHeader(1, DProxyPacketType.HEARTBEAT_RESPONSE, 8 + 8, DProxyError.NO_ERROR);

public record DProxyErrorPacket(DProxyError ErrorCode, string Message) : DProxyHeader(1, DProxyPacketType.ERROR, (ushort)(2 + Encoding.UTF8.GetByteCount(Message)), ErrorCode);
