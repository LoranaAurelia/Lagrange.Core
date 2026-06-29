namespace Lagrange.Core.Internal.Packets;

using Lagrange.Core.Internal.Packets.System;

internal class SsoPacket
{
    public byte PacketType { get; set; }

    public string Command { get; }

    public uint Sequence { get; }

    public byte[] Payload { get; }

    public int RetCode { get; }

    public string? Extra { get; }

    public byte[] ReserveField { get; init; } = Array.Empty<byte>();

    public SsoReserveFields? ReserveFields { get; init; }

    public IReadOnlyDictionary<string, object>? SignMetadata { get; init; }

    public SsoPacket(byte packetType, string command, uint sequence, byte[] payload)
    {
        PacketType = packetType;
        Command = command;
        Sequence = sequence;
        Payload = payload;
    }

    public SsoPacket(byte packetType, string command, uint sequence, int retCode, string extra)
    {
        PacketType = packetType;
        Command = command;
        Sequence = sequence;
        RetCode = retCode;
        Payload = Array.Empty<byte>();
        Extra = extra;
    }
}
