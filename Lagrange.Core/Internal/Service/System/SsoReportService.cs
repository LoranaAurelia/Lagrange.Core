using Lagrange.Core.Common;
using Lagrange.Core.Internal.Event;
using Lagrange.Core.Internal.Event.System;

namespace Lagrange.Core.Internal.Service.System;

[EventSubscribe(typeof(SsoReportEvent))]
[Service("trpc.o3.report.Report.SsoReport")]
internal class SsoReportService : BaseService<SsoReportEvent>
{
    protected override bool Build(SsoReportEvent input, BotKeystore keystore, BotAppInfo appInfo,
        BotDeviceInfo device, out Span<byte> output, out List<Memory<byte>>? extraPackets)
    {
        // The confirmed SsoReport body is supplied by the routed SignServer endpoint.
        output = Array.Empty<byte>();
        extraPackets = null;
        return true;
    }

    protected override bool Parse(Span<byte> input, BotKeystore keystore, BotAppInfo appInfo, BotDeviceInfo device,
        out SsoReportEvent output, out List<ProtocolEvent>? extraEvents)
    {
        output = SsoReportEvent.Result();
        extraEvents = null;
        return true;
    }
}
