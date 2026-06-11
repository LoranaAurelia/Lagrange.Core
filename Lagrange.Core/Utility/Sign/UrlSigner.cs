using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Lagrange.Core.Utility.Sign;

internal class UrlSigner : SignProvider
{
    private readonly string? _signServer;

    private readonly HttpClient _client = new();

    private readonly bool _advancedMode;

    public override bool UseNativeBodyForOnline => _advancedMode;

    public UrlSigner(string? url)
    {
        _signServer = url;
        _advancedMode = ProbeAdvancedMode();
    }

    public override byte[]? Sign(string cmd, uint seq, byte[] body, out byte[]? e, out string? t)
    {

        e = null;
        t = null;

        if (!WhiteListCommand.Contains(cmd)) return null;
        if (_signServer == null) throw new Exception("Sign server is not configured");
        if (!_advancedMode && SignProvider.IsRoutedOnlineCommand(cmd)) return null;

        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri(_signServer),
            Content = JsonContent.Create(new JsonObject
            {
                { "cmd", cmd },
                { "seq", seq },
                { "src", Convert.ToHexString(body) }
            })
        };

        using var message = _client.Send(request);
        if (message.StatusCode != HttpStatusCode.OK) throw new Exception($"Signer server returned a {message.StatusCode}");
        var json = JsonDocument.Parse(message.Content.ReadAsStream()).RootElement;

        var valueJson = json.GetProperty("value");
        var extraJson = valueJson.GetProperty("extra");
        var tokenJson = valueJson.GetProperty("token");
        var signJson = valueJson.GetProperty("sign");

        string? token = tokenJson.GetString();
        string? extra = extraJson.GetString();
        e = extra != null ? Convert.FromHexString(extra) : Array.Empty<byte>();
        t = token != null ? Encoding.UTF8.GetString(Convert.FromHexString(token)) : "";
        string sign = signJson.GetString() ?? throw new Exception("Signer server returned an empty sign");
        return Convert.FromHexString(sign);
    }

    public override SignResult SignPacket(SignRequestContext context)
    {
        if (!WhiteListCommand.Contains(context.Command)) return new SignResult();
        if (_signServer == null) throw new Exception("Sign server is not configured");

        string? route = _advancedMode ? GetRoutedEndpoint(context.Command) : null;
        if (route == null)
        {
            if (SignProvider.IsRoutedOnlineCommand(context.Command)) return new SignResult();
            return SendSignRequest(context, true);
        }

        try
        {
            return SendSignRequest(context, false, route);
        }
        catch
        {
            if (SignProvider.IsRoutedOnlineCommand(context.Command)) return new SignResult();
            return SendSignRequest(context, true);
        }
    }

    private SignResult SendSignRequest(SignRequestContext context, bool legacy, string? route = null)
    {
        string endpoint = route == null ? _signServer! : $"{_signServer!.TrimEnd('/')}/{route}";
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri(endpoint),
            Content = JsonContent.Create(BuildRequestContext(context, legacy ? context.Command : null))
        };

        using var message = _client.Send(request);
        if (message.StatusCode != HttpStatusCode.OK) throw new Exception($"Signer server returned a {message.StatusCode}");
        var json = JsonDocument.Parse(message.Content.ReadAsStream()).RootElement;
        return ParseSignResult(json);
    }

    private static JsonObject BuildRequestContext(SignRequestContext context, string? cmd)
    {
        var machineId = Convert.ToHexString(SHA256.HashData(context.DeviceInfo.Guid.ToByteArray())).ToLowerInvariant()[..32];
        var request = new JsonObject
        {
            { "session", $"lagrange-{context.AppInfo.AppClientVersion}-u{context.Keystore.Uin}-{context.DeviceInfo.Guid:N}" },
            { "uin", context.Keystore.Uin.ToString() },
            { "seq", context.Sequence },
            { "src", Convert.ToHexString(context.Body) },
            { "qua", $"V1_LNX_NQ_{context.AppInfo.CurrentVersion.Replace("-", "_")}_GW_B" },
            { "machine_id", machineId },
            { "fake_hostname", "aurora-t14" },
            { "fake_proc_comm", "qq" },
            { "fake_proc_cmdline", "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService" },
            { "fake_device_name", context.DeviceInfo.DeviceName },
            { "fake_hardware_model", "Lenovo ThinkPad T14 Gen 3" },
            { "fake_os_release", $"{context.DeviceInfo.SystemKernel} x86_64" },
            { "fake_timezone", "Asia/Shanghai" }
        };

        if (cmd != null) request["cmd"] = cmd;
        return request;
    }

    private static SignResult ParseSignResult(JsonElement json)
    {
        var valueJson = json.GetProperty("value");
        string? token = TryGetString(valueJson, "token");
        string? extra = TryGetString(valueJson, "extra");
        string? sign = TryGetString(valueJson, "sign");
        string? nativeBody = TryGetString(valueJson, "native_body");

        return new SignResult
        {
            Sign = string.IsNullOrEmpty(sign) ? null : Convert.FromHexString(sign),
            Extra = string.IsNullOrEmpty(extra) ? Array.Empty<byte>() : Convert.FromHexString(extra),
            Token = string.IsNullOrEmpty(token) ? "" : Encoding.UTF8.GetString(Convert.FromHexString(token)),
            NativeBody = string.IsNullOrEmpty(nativeBody) ? null : Convert.FromHexString(nativeBody),
            NativeTier = TryGetString(valueJson, "native_tier")
        };
    }

    private bool ProbeAdvancedMode()
    {
        if (string.IsNullOrEmpty(_signServer)) return false;

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_signServer.TrimEnd('/')}/advanced-mode");
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1500));
            using var response = _client.Send(request, cts.Token);
            if (!response.IsSuccessStatusCode) return false;

            var json = JsonDocument.Parse(response.Content.ReadAsStream()).RootElement;
            return json.TryGetProperty("advanced_mode", out var advanced) && advanced.ValueKind == JsonValueKind.True;
        }
        catch
        {
            return false;
        }
    }

    private static string? GetRoutedEndpoint(string command) => command switch
    {
        "trpc.msg.register_proxy.RegisterProxy.SsoInfoSync" => "online/sso-info-sync",
        "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat" => "online/heartbeat",
        "trpc.qq_new_tech.status_svc.StatusService.Register" => "online/status-register",
        "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey" => "secure/establish-share-key",
        "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess" => "secure/secure-access",
        _ => null
    };

    private static string? TryGetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.GetString()
            : null;
}
