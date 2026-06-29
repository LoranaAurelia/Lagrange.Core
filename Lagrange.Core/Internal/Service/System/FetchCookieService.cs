using System.Text;
using Lagrange.Core.Common;
using Lagrange.Core.Internal.Event;
using Lagrange.Core.Internal.Event.System;
using Lagrange.Core.Internal.Packets.Service.Oidb;
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
        var expireAt = fetchedAt.AddDays(1);
        var cookies = new List<string>(packet.Body.Urls.Count);

        foreach (var url in packet.Body.Urls)
        {
            string cookie = Encoding.UTF8.GetString(url.Value);
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
