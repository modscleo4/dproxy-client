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

using System.Net;
using System.Net.Sockets;

namespace DProxyClient;

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

    public static IPAddress GetUnmapped(this IPAddress address)
    {
        return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
    }

    /// <summary>
    /// Checks if the IP address is private (RFC 1918 for IPv4 and RFC 4193 for IPv6).
    /// </summary>
    public static bool IsPrivate(this IPAddress address)
    {
        switch (address.AddressFamily) {
            case AddressFamily.InterNetwork: {
                var bytes = address.GetAddressBytes();
                return bytes[0] == 10
                       || (bytes[0] == 172 && (bytes[1] >= 16 && bytes[1] <= 31))
                       || (bytes[0] == 192 && bytes[1] == 168);
            }
            case AddressFamily.InterNetworkV6: {
                var bytes = address.GetAddressBytes();
                return ((bytes[0] & 0xFE) == 0xFC); // Unique Local Address (ULA)
            }
            default:
                return false;
        }
    }

    /// <summary>
    /// Checks if the IP address is link-local (RFC 3927 for IPv4 and RFC 4291 for IPv6).
    /// </summary>
    public static bool IsLinkLocal(this IPAddress address)
    {
        switch (address.AddressFamily) {
            case AddressFamily.InterNetwork: {
                var bytes = address.GetAddressBytes();
                return (bytes[0] == 169 && bytes[1] == 254);
            }
            case AddressFamily.InterNetworkV6: {
                var bytes = address.GetAddressBytes();
                return (bytes[0] == 0xfe && (bytes[1] & 0xc0) == 0x80); // fe80::/10
            }
            default:
                return false;
        }
    }

    /// <summary>
    /// Checks if the IP address is multicast (RFC 5771 for IPv4 and RFC 4291 for IPv6).
    /// </summary>
    public static bool IsMulticast(this IPAddress address)
    {
        switch (address.AddressFamily) {
            case AddressFamily.InterNetwork: {
                var bytes = address.GetAddressBytes();
                return (bytes[0] >= 224 && bytes[0] <= 239);
            }
            case AddressFamily.InterNetworkV6: {
                var bytes = address.GetAddressBytes();
                return (bytes[0] == 0xff);
            }
            default:
                return false;
        }
    }

    /// <summary>
    /// Checks if the IP address is special-purpose (RFC 6890).
    /// </summary>
    public static bool IsSpecial(this IPAddress address)
    {
        switch (address.AddressFamily) {
            case AddressFamily.InterNetwork: {
                var bytes = address.GetAddressBytes();
                // 100.64.0.0/10 (CGNAT)
                // 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
                // 198.18.0.0/15 (Benchmarking)
                // 240.0.0.0/4 (Reserved for Future Use)
                return (bytes[0] == 100 && (bytes[1] >= 64 && bytes[1] <= 127))
                       || (bytes[0] == 192 && bytes[1] == 0 && bytes[2] == 2)
                       || (bytes[0] == 198 && bytes[1] == 51 && bytes[2] == 100)
                       || (bytes[0] == 203 && bytes[1] == 0 && bytes[2] == 113)
                       || (bytes[0] == 198 && (bytes[1] >= 18 && bytes[1] <= 19))
                       || (bytes[0] >= 240);
            }
            case AddressFamily.InterNetworkV6: {
                var bytes = address.GetAddressBytes();
                // 2001:db8::/32 (Documentation Address)
                return (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8);
            }
            default:
                return false;
        }
    }

    public static bool IsNonPublic(this IPAddress address)
    {
        address = address.GetUnmapped();
        return IPAddress.IsLoopback(address) || address.IsPrivate() || address.IsLinkLocal() || address.IsMulticast() || address.IsSpecial();
    }
}
