using Lagrange.Core.Common;
using Lagrange.Core.Internal.Event;
using Lagrange.Core.Internal.Event.System;
using Lagrange.Core.Internal.Packets.Service.Oidb;
using Lagrange.Core.Internal.Packets.Service.Oidb.Request;
using Lagrange.Core.Internal.Packets.Service.Oidb.Response;
using Lagrange.Core.Utility.Extension;
using ProtoBuf;

namespace Lagrange.Core.Internal.Service.System;

[EventSubscribe(typeof(FetchClientKeyEvent))]
[Service("OidbSvcTrpcTcp.0x102a_1")]
internal class FetchClientKeyService : BaseService<FetchClientKeyEvent>
{
    protected override bool Build(FetchClientKeyEvent input, BotKeystore keystore, BotAppInfo appInfo,
        BotDeviceInfo device, out Span<byte> output, out List<Memory<byte>>? extraPackets)
    {
        var packet = new OidbSvcTrpcTcpBase<OidbSvcTrpcTcp0x102A_1>(new OidbSvcTrpcTcp0x102A_1());

        output = packet.Serialize();
        extraPackets = null;
        return true;
    }

    protected override bool Parse(Span<byte> input, BotKeystore keystore, BotAppInfo appInfo, BotDeviceInfo device,
        out FetchClientKeyEvent output, out List<ProtocolEvent>? extraEvents)
    {
        var packet = Serializer.Deserialize<OidbSvcTrpcTcpBase<OidbSvcTrpcTcp0x102A_1Response>>(input);
        var fetchedAt = DateTime.UtcNow;
        string clientKey = packet.Body?.ClientKey ?? "";
        uint expiration = packet.Body?.Expiration ?? 0;

        keystore.Session.Oidb102AClientKey = new BotKeystore.Oidb102AClientKeyCache
        {
            ClientKey = clientKey,
            RawExpiration = expiration,
            FetchedAtUtc = fetchedAt,
            ExpireAtUtc = ResolveExpiration(expiration, fetchedAt)
        };

        output = FetchClientKeyEvent.Result((int)packet.ErrorCode, clientKey, expiration);
        extraEvents = null;
        return true;
    }

    private static DateTime? ResolveExpiration(uint expiration, DateTime fetchedAtUtc)
    {
        if (expiration == 0) return null;

        long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (expiration > now - 86400) return DateTimeOffset.FromUnixTimeSeconds(expiration).UtcDateTime;

        return fetchedAtUtc.AddSeconds(expiration);
    }
}
