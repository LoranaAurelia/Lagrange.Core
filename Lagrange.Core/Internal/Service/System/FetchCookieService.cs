using System.Text;
using Lagrange.Core.Common;
using Lagrange.Core.Internal.Event;
using Lagrange.Core.Internal.Event.System;
using Lagrange.Core.Internal.Packets.Service.Oidb;
using Lagrange.Core.Internal.Packets.Service.Oidb.Generics;
using Lagrange.Core.Internal.Packets.Service.Oidb.Request;
using Lagrange.Core.Internal.Packets.Service.Oidb.Response;
using Lagrange.Core.Utility.Extension;
using ProtoBuf;

namespace Lagrange.Core.Internal.Service.System;

[EventSubscribe(typeof(FetchCookieEvent))]
[Service("OidbSvcTrpcTcp.0x102a_0")]
internal class FetchCookieService : BaseService<FetchCookieEvent>
{
    protected override bool Build(FetchCookieEvent input, BotKeystore keystore, BotAppInfo appInfo,
        BotDeviceInfo device, out Span<byte> output, out List<Memory<byte>>? extraPackets)
    {
        var packet = new OidbSvcTrpcTcpBase<OidbSvcTrpcTcp0x102A_0>(new OidbSvcTrpcTcp0x102A_0
        {
            Domain = input.Domains
        });

        output = packet.Serialize();
        extraPackets = null;
        return true;
    }

    protected override bool Parse(Span<byte> input, BotKeystore keystore, BotAppInfo appInfo, BotDeviceInfo device,
        out FetchCookieEvent output, out List<ProtocolEvent>? extraEvents)
    {
        var packet = Serializer.Deserialize<OidbSvcTrpcTcpBase<OidbSvcTrpcTcp0x102A_0Response>>(input);
        var fetchedAt = DateTime.UtcNow;
        var expireAt = fetchedAt.AddMinutes(20);
        var urls = packet.Body?.Urls ?? new List<OidbProperty>();
        var cookies = new List<string>(urls.Count);

        foreach (var url in urls)
        {
            if (url == null) continue;

            string cookie = url.Value is { Length: > 0 } value
                ? Encoding.UTF8.GetString(value)
                : "";
            cookies.Add(cookie);

            if (!string.IsNullOrWhiteSpace(url.Key))
            {
                keystore.Session.Oidb102ACookies[url.Key] = new BotKeystore.Oidb102ACookieCache
                {
                    Domain = url.Key,
                    Cookie = cookie,
                    FetchedAtUtc = fetchedAt,
                    ExpireAtUtc = expireAt
                };
            }
        }

        output = FetchCookieEvent.Result((int)packet.ErrorCode, cookies);
        extraEvents = null;
        return true;
    }
}
