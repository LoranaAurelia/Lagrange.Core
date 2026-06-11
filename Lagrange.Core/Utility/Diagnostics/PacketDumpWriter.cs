using System.Text.Json;
using Lagrange.Core.Common;
using Lagrange.Core.Internal.Packets;
using Lagrange.Core.Utility.Extension;

namespace Lagrange.Core.Utility.Diagnostics;

internal static class PacketDumpWriter
{
    private static readonly object Lock = new();

    public static void DumpUnsupportedSsoPacket(BotConfig config, SsoPacket packet)
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

            var metadata = new
            {
                time = DateTimeOffset.Now,
                kind = "unsupported_sso_frame",
                packet_type = packet.PacketType,
                command = packet.Command,
                sequence = packet.Sequence,
                ret_code = packet.RetCode,
                extra = packet.Extra,
                payload_len = packet.Payload.Length,
                payload_hex = packet.Payload.Hex(true),
                payload_file = Path.GetFileName(payloadPath),
                reserve_len = packet.ReserveField.Length,
                reserve_hex = packet.ReserveField.Hex(true),
                reserve_file = packet.ReserveField.Length == 0 ? null : Path.GetFileName(reservePath)
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

    private static string SanitizeFileName(string value)
    {
        var invalidChars = Path.GetInvalidFileNameChars();
        var chars = value.Select(ch => invalidChars.Contains(ch) || ch is '.' or '/' or '\\' ? '_' : ch).ToArray();
        string sanitized = new string(chars);
        return sanitized.Length <= 120 ? sanitized : sanitized[..120];
    }
}
