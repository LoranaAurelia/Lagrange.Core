using System.Text.Json;
using System.Security.Cryptography;
using Lagrange.Core.Common;
using Lagrange.Core.Internal.Packets;
using Lagrange.Core.Utility.Extension;

namespace Lagrange.Core.Utility.Diagnostics;

internal static class PacketDumpWriter
{
    private static readonly object Lock = new();

    public static void DumpUnsupportedSsoPacket(BotConfig config, SsoPacket packet)
        => DumpSsoPacket(config, packet, "unsupported_sso_frame");

    public static void DumpParseErrorSsoPacket(BotConfig config, SsoPacket packet, Exception exception)
        => DumpSsoPacket(config, packet, "sso_frame_parse_error", exception);

    private static void DumpSsoPacket(BotConfig config, SsoPacket packet, string kind, Exception? exception = null)
    {
        if (!config.EnableFileLogging) return;

        try
        {
            string packetDirectory = Path.Combine(config.LogDirectory, "packets");
            Directory.CreateDirectory(packetDirectory);

            string timestamp = DateTimeOffset.Now.ToString("yyyyMMdd-HHmmss-fff");
            string command = SanitizeFileName(packet.Command);
            string fileBase = $"{timestamp}_{packet.Sequence}_{command}";
            string payloadPath = Path.Combine(packetDirectory, $"{fileBase}.payload.bin");
            string reservePath = Path.Combine(packetDirectory, $"{fileBase}.reserve.bin");
            string metadataPath = Path.Combine(packetDirectory, $"{fileBase}.json");
            string payloadSha256 = Sha256_16(packet.Payload);
            string reserveSha256 = Sha256_16(packet.ReserveField);

            var metadata = new
            {
                time = DateTimeOffset.Now,
                kind,
                packet_type = packet.PacketType,
                command = packet.Command,
                sequence = packet.Sequence,
                ret_code = packet.RetCode,
                extra = packet.Extra,
                payload_len = packet.Payload.Length,
                payload_sha256_16 = payloadSha256,
                payload_hex = packet.Payload.Hex(true),
                payload_file = Path.GetFileName(payloadPath),
                reserve_len = packet.ReserveField.Length,
                reserve_sha256_16 = reserveSha256,
                reserve_hex = packet.ReserveField.Hex(true),
                reserve_file = packet.ReserveField.Length == 0 ? null : Path.GetFileName(reservePath),
                error_type = exception?.GetType().FullName,
                error_message = exception?.Message,
                error_stack = exception?.StackTrace
            };

            lock (Lock)
            {
                File.WriteAllBytes(payloadPath, packet.Payload);
                if (packet.ReserveField.Length > 0) File.WriteAllBytes(reservePath, packet.ReserveField);
                File.WriteAllText(metadataPath, JsonSerializer.Serialize(metadata, new JsonSerializerOptions
                {
                    WriteIndented = true
                }));
            }
        }
        catch
        {
            // Packet dumping is diagnostics-only and must not affect packet dispatch.
        }
    }

    private static string Sha256_16(byte[] bytes)
        => bytes.Length == 0 ? "" : Convert.ToHexString(SHA256.HashData(bytes))[..16];

    private static string SanitizeFileName(string value)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        var chars = value.Select(ch => invalidChars.Contains(ch) || ch is '.' or '/' or '\\' ? '_' : ch).ToArray();
        string sanitized = new string(chars);
        return sanitized.Length <= 120 ? sanitized : sanitized[..120];
    }
}
