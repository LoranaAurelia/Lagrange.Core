using System.Text;
using Lagrange.Core.Common;
using Lagrange.Core.Internal.Event;
using Lagrange.Core.Internal.Event.System;

namespace Lagrange.Core.Internal.Service.System;

[Service("StatSvc.SvcReqMSFLoginNotify")]
internal class LoginNotifyService : BaseService<LoginNotifyEvent>
{
    private const int TypeOffset = 0x74;

    protected override bool Parse(Span<byte> input, BotKeystore keystore, BotAppInfo appInfo, BotDeviceInfo device,
        out LoginNotifyEvent output, out List<ProtocolEvent>? extraEvents)
    {
        extraEvents = null;

        var payload = input.ToArray();
        string text = Encoding.UTF8.GetString(payload);
        bool isLogin = text.Contains("Login Notification", StringComparison.OrdinalIgnoreCase) ||
                       (payload.Length > TypeOffset && payload[TypeOffset] == 0x01);
        bool isLogoff = text.Contains("Logoff Notification", StringComparison.OrdinalIgnoreCase) ||
                        (payload.Length > TypeOffset && payload[TypeOffset] == 0x02);

        string tag = isLogoff ? "Logoff Notification" : "Login Notification";
        string message = isLogoff
            ? "Your accout is logged off in a mobile"
            : "Your accout is logged on in a mobile";

        output = LoginNotifyEvent.Result(!isLogoff && isLogin, 0, tag, message);
        return isLogin || isLogoff;
    }
}
