using System.Text;
using Lagrange.Core.Common;
using Lagrange.Core.Internal.Event;
using Lagrange.Core.Internal.Event.System;

namespace Lagrange.Core.Internal.Service.System;

[Service("StatSvc.SvcReqMSFLoginNotify")]
internal class LoginNotifyService : BaseService<LoginNotifyEvent>
{
    private const int TypeOffset = 0x74;
    private static readonly string[] NotifyMarkers =
    {
        "SvcReqMSFLoginNotify",
        "QQService.SvcReqMSFLoginNotify",
        "MSFLoginNotify",
        "Login Notification",
        "Logoff Notification",
        "logged on",
        "logged off"
    };

    private static readonly string[] LoginMarkers =
    {
        "Login Notification",
        "logged on",
        "logged in",
        "is logged on",
        "is logged in",
        "上线",
        "登录"
    };

    private static readonly string[] LogoffMarkers =
    {
        "Logoff Notification",
        "logged off",
        "logged out",
        "is logged off",
        "is logged out",
        "下线",
        "退出"
    };

    protected override bool Parse(Span<byte> input, BotKeystore keystore, BotAppInfo appInfo, BotDeviceInfo device,
        out LoginNotifyEvent output, out List<ProtocolEvent>? extraEvents)
    {
        extraEvents = null;

        var payload = input.ToArray();
        string text = Encoding.UTF8.GetString(payload);
        bool hasNotifyMarker = ContainsAny(text, NotifyMarkers);
        bool offsetLogin = payload.Length > TypeOffset && payload[TypeOffset] == 0x01;
        bool offsetLogoff = payload.Length > TypeOffset && payload[TypeOffset] == 0x02;
        bool isLogin = ContainsAny(text, LoginMarkers) || (hasNotifyMarker && offsetLogin);
        bool isLogoff = ContainsAny(text, LogoffMarkers) || (hasNotifyMarker && offsetLogoff);

        if (!hasNotifyMarker && !isLogin && !isLogoff)
        {
            output = null!;
            return false;
        }

        bool stateKnown = isLogin != isLogoff;
        string tag = stateKnown
            ? isLogoff ? "Logoff Notification" : "Login Notification"
            : "MSF Login Notify";
        string message = stateKnown
            ? isLogoff ? "Device is logged off" : "Device is logged on"
            : ExtractDisplayMessage(text);

        output = LoginNotifyEvent.Result(isLogin && !isLogoff, stateKnown, 0, tag, message);
        return true;
    }

    private static bool ContainsAny(string text, string[] markers)
        => markers.Any(marker => text.Contains(marker, StringComparison.OrdinalIgnoreCase));

    private static string ExtractDisplayMessage(string text)
    {
        var parts = text.Split('\0', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(part => part.Any(char.IsLetterOrDigit))
            .Where(part => part.Length <= 160)
            .ToArray();

        return parts.Length == 0 ? "Unknown MSF login notify" : string.Join(" | ", parts.TakeLast(Math.Min(parts.Length, 3)));
    }
}
