namespace Lagrange.Core.Internal.Event.System;

internal class SsoReportEvent : ProtocolEvent
{
    private SsoReportEvent() : base(false) { }

    private SsoReportEvent(int resultCode) : base(resultCode) { }

    public static SsoReportEvent Create() => new();

    public static SsoReportEvent Result() => new(0);
}
