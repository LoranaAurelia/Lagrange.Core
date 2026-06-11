using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Lagrange.Core.Common;
using Lagrange.Core.Utility.Sign;
using Lagrange.OneBot.Utility.Fallbacks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Lagrange.OneBot.Utility;

public class OneBotSigner : SignProvider
{
    private readonly IConfiguration _configuration;

    private readonly ILogger<OneBotSigner> _logger;

    private const string Url = "https://sign.lagrangecore.org/api/sign/39038";

    private readonly SignServerProfileStore _profileStore;

    private readonly string? _signServer;

    private readonly HttpClient _client;

    private readonly BotAppInfo? _info;

    private readonly string platform;

    private readonly string version;

    private readonly bool _advancedMode;

    private readonly string _mode;

    private readonly bool _strictNativeTier;

    public override bool UseNativeBodyForOnline => _advancedMode && (_mode == "native-body-online" || _mode == "strict");

    public override bool StrictNativeTier => _strictNativeTier || _mode == "strict";

    public OneBotSigner(IConfiguration config, ILogger<OneBotSigner> logger, SignServerProfileStore profileStore)
    {
        _configuration = config;
        _logger = logger;
        _profileStore = profileStore;

        _signServer = string.IsNullOrEmpty(config["SignServerUrl"]) ? Url : config["SignServerUrl"];
        if (_signServer == "https://lwxmagic.sealdice.com/api/sign") {
            _signServer = "$(SIGN_SERVER_DEFAULT)";
        } else if (_signServer == "https://lwxmagic.sealdice.com/api/sign/39038") {
            _signServer = "$(SIGN_SERVER_DEFAULT)/39038";
        }

        string? signProxyUrl = config["SignProxyUrl"]; // Only support HTTP proxy

        _client = new HttpClient(handler: new HttpClientHandler
        {
            Proxy = string.IsNullOrEmpty(signProxyUrl) ? null : new WebProxy()
            {
                Address = new Uri(signProxyUrl),
                BypassProxyOnLocal = false,
                UseDefaultCredentials = false,
            },
        }, disposeHandler: true);

        if (string.IsNullOrEmpty(_signServer)) logger.LogWarning("Signature Service is not available, login may be failed");

        _mode = (config["SignServer:Mode"] ?? "native-body-online").ToLowerInvariant();
        _strictNativeTier = config.GetValue("SignServer:StrictNativeTier", false);
        _info ??= GetAppInfo();
        platform = _info.Os switch
        {
            "Windows" => "Windows",
            "Mac" => "MacOs",
            "Linux" => "Linux",
            _ => "Unknown"
        };
        version = _info.CurrentVersion;
        _advancedMode = ProbeAdvancedMode();
    }

    public override byte[]? Sign(string cmd, uint seq, byte[] body, [UnscopedRef] out byte[]? e, [UnscopedRef] out string? t)
    {
        e = null;
        t = null;

        if (!WhiteListCommand.Contains(cmd)) return null;
        if (_signServer == null) throw new Exception("Sign server is not configured");
        if (!_advancedMode && SignProvider.IsRoutedOnlineCommand(cmd)) return null;

        var result = SendSignRequest(cmd, seq, body, null, true);
        e = result.Extra;
        t = result.Token;
        return result.Sign;
    }

    public override SignResult SignPacket(SignRequestContext context)
    {
        if (!WhiteListCommand.Contains(context.Command)) return new SignResult();
        if (_signServer == null) throw new Exception("Sign server is not configured");

        string? route = _advancedMode ? GetRoutedEndpoint(context.Command) : null;
        if (route == null || _mode == "legacy")
        {
            if (SignProvider.IsRoutedOnlineCommand(context.Command)) return new SignResult();
            return SendSignRequest(context.Command, context.Sequence, context.Body, context, true);
        }

        try
        {
            var routed = SendSignRequest(context.Command, context.Sequence, context.Body, context, false, route);
            LogSignResult(context.Command, context.Sequence, routed);
            EnforceNativeResult(context.Command, routed);
            return routed;
        }
        catch (Exception e) when (!StrictNativeTier)
        {
            _logger.LogWarning(e, "Routed SignServer endpoint failed for {Command}, falling back to legacy signing", context.Command);
            if (SignProvider.IsRoutedOnlineCommand(context.Command)) return new SignResult();
            return SendSignRequest(context.Command, context.Sequence, context.Body, context, true);
        }
    }

    public override void PushState(SignStatePushContext context)
    {
        if (!_advancedMode || string.IsNullOrEmpty(_signServer)) return;

        try
        {
            var profile = _profileStore.GetProfile();
            var payloadHash = Sha256_16(context.Payload);
            var reserveHash = Sha256_16(context.ReserveField);
            UpdateProfileState(profile, context.ReserveFields, context.ReserveField);
            var statePush = new JsonObject
            {
                { "command", context.Command },
                { "seq", context.Sequence },
                { "payload_len", context.Payload.Length },
                { "payload_sha256_16", payloadHash },
                { "reserve_len", context.ReserveField.Length },
                { "reserve_sha256_16", reserveHash },
                { "transinfo", BuildTransInfoMetadata(context.ReserveFields) }
            };

            var requestJson = BuildRequestContext(profile, context.Keystore.Uin, 0, Array.Empty<byte>(), null);
            requestJson.Remove("seq");
            requestJson.Remove("src");
            requestJson["state_push"] = statePush;

            using var request = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = new Uri($"{_signServer.TrimEnd('/')}/state/push"),
                Content = JsonContent.Create(requestJson)
            };

            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(
                _configuration.GetValue("SignServer:StatePushTimeoutMs", 1000)));
            using var response = _client.Send(request, cts.Token);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogDebug("SignServer state push returned {StatusCode}", response.StatusCode);
            }
        }
        catch (Exception e)
        {
            _logger.LogDebug(e, "SignServer state push failed");
        }
    }

    private SignResult SendSignRequest(string cmd, uint seq, byte[] body, SignRequestContext? context, bool legacy, string? route = null)
    {
        var profile = _profileStore.GetProfile();
        var requestJson = BuildRequestContext(profile, context?.Keystore.Uin ?? 0, seq, body, legacy ? cmd : null);
        string endpoint = route == null ? _signServer! : $"{_signServer!.TrimEnd('/')}/{route}";
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri(endpoint),
            Content = JsonContent.Create(requestJson)
        };

        using var message = _client.Send(request);
        if (message.StatusCode != HttpStatusCode.OK) throw new Exception($"Signer server returned a {message.StatusCode}");
        var json = JsonDocument.Parse(message.Content.ReadAsStream()).RootElement;

        if (json.TryGetProperty("platform", out JsonElement platformJson))
        {
            if (platformJson.GetString() != platform) throw new Exception("Signer platform mismatch");
        }
        else
        {
            _logger.LogWarning("Signer platform miss");
        }

        if (json.TryGetProperty("version", out JsonElement versionJson))
        {
            if (versionJson.GetString() != version) throw new Exception("Signer version mismatch");
        }
        else
        {
            _logger.LogWarning("Signer version miss");
        }

        var result = ParseSignResult(json);
        if (!string.IsNullOrEmpty(result.NativeTier))
        {
            profile.OnlineState.LastNativeTiers[cmd] = result.NativeTier;
            if (cmd == "trpc.msg.register_proxy.RegisterProxy.SsoInfoSync") profile.OnlineState.LastSsoInfoSyncSeq = seq;
            if (cmd == "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat") profile.OnlineState.LastHeartbeatSeq = seq;
            _profileStore.Save(profile);
        }

        return result;
    }

    private JsonObject BuildRequestContext(SignServerProfile profile, uint uin, uint seq, byte[] body, string? cmd)
    {
        if (uin != 0 && profile.Identity.Uin != uin.ToString())
        {
            profile.Identity.Uin = uin.ToString();
            _profileStore.Save(profile);
        }

        var environment = profile.Environment;
        var request = new JsonObject
        {
            { "session", profile.Identity.Session },
            { "uin", uin == 0 ? profile.Identity.Uin : uin.ToString() },
            { "seq", seq },
            { "src", Convert.ToHexString(body) },
            { "qua", profile.App.Qua },
            { "machine_id", profile.Identity.MachineId },
            { "fake_hostname", environment.FakeHostname },
            { "fake_proc_comm", environment.FakeProcComm },
            { "fake_proc_cmdline", environment.FakeProcCmdline },
            { "fake_device_name", environment.FakeDeviceName },
            { "fake_hardware_model", environment.FakeHardwareModel },
            { "fake_os_release", environment.FakeOsRelease },
            { "fake_timezone", environment.FakeTimezone }
        };

        if (cmd != null) request["cmd"] = cmd;
        return request;
    }

    private SignResult ParseSignResult(JsonElement json)
    {
        var valueJson = json.GetProperty("value");
        string? token = TryGetString(valueJson, "token");
        string? extra = TryGetString(valueJson, "extra");
        string? sign = TryGetString(valueJson, "sign");
        string? nativeBody = TryGetString(valueJson, "native_body");
        string? nativeTier = TryGetString(valueJson, "native_tier");

        return new SignResult
        {
            Sign = string.IsNullOrEmpty(sign) ? null : Convert.FromHexString(sign),
            Extra = string.IsNullOrEmpty(extra) ? Array.Empty<byte>() : Convert.FromHexString(extra),
            Token = string.IsNullOrEmpty(token) ? "" : Encoding.UTF8.GetString(Convert.FromHexString(token)),
            NativeBody = string.IsNullOrEmpty(nativeBody) ? null : Convert.FromHexString(nativeBody),
            NativeTier = nativeTier,
            StateUpdates = ParseStateUpdates(valueJson),
            Diagnostic = valueJson.TryGetProperty("diagnostic", out var diagnostic) ? diagnostic.GetRawText() : null
        };
    }

    public BotAppInfo GetAppInfo()
    {
        if (_info != null) return _info;

        return FallbackAsync<BotAppInfo>.Create()
            .Add(async token =>
            {
                try { return await _client.GetFromJsonAsync<BotAppInfo>($"{_signServer}/appinfo", token); }
                catch { return null; }
            })
            .Add(token =>
            {
                string path = _configuration["ConfigPath:AppInfo"] ?? "appinfo.json";

                if (!File.Exists(path)) return Task.FromResult(null as BotAppInfo);

                try { return Task.FromResult(JsonSerializer.Deserialize<BotAppInfo>(File.ReadAllText(path))); }
                catch { return Task.FromResult(null as BotAppInfo); }
            })
            .ExecuteAsync(token => Task.FromResult(
                BotAppInfo.ProtocolToAppInfo[_configuration["Account:Protocol"] switch
                {
                    "Windows" => Protocols.Windows,
                    "MacOs" => Protocols.MacOs,
                    _ => Protocols.Linux,
                }]
            ))
            .Result;
    }

    private bool ProbeAdvancedMode()
    {
        if (string.IsNullOrEmpty(_signServer)) return false;

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_signServer.TrimEnd('/')}/advanced-mode");
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(
                _configuration.GetValue("SignServer:AdvancedProbeTimeoutMs", 1500)));
            using var response = _client.Send(request, cts.Token);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogInformation("SignServer advanced-mode probe returned {StatusCode}; using legacy signing", response.StatusCode);
                return false;
            }

            var json = JsonDocument.Parse(response.Content.ReadAsStream()).RootElement;
            bool enabled = json.TryGetProperty("advanced_mode", out var modeJson) &&
                           modeJson.ValueKind == JsonValueKind.True;
            if (!enabled) _logger.LogInformation("SignServer advanced_mode is not enabled; using legacy signing");
            return enabled;
        }
        catch (Exception e)
        {
            _logger.LogInformation(e, "SignServer advanced-mode probe failed; using legacy signing");
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

    private void LogSignResult(string command, uint seq, SignResult result)
    {
        _logger.LogInformation(
            "SignServer routed command={Command} seq={Sequence} native_tier={NativeTier} native_body_len={NativeBodyLen} sign_len={SignLen} token_len={TokenLen} extra_len={ExtraLen}",
            command,
            seq,
            result.NativeTier ?? "",
            result.NativeBody?.Length ?? 0,
            result.Sign?.Length ?? 0,
            result.Token?.Length ?? 0,
            result.Extra?.Length ?? 0);
    }

    private void EnforceNativeResult(string command, SignResult result)
    {
        if (SignProvider.IsRoutedOnlineCommand(command) &&
            result.NativeBody is { Length: > 0 } &&
            !SignProvider.CanReplaceWithNativeBody(command, result.NativeBody))
        {
            _logger.LogWarning(
                "SignServer native_body ignored for {Command}: native_body_len={NativeBodyLen}",
                command,
                result.NativeBody.Length);
        }

        if (!StrictNativeTier) return;

        string? expected = command switch
        {
            "trpc.msg.register_proxy.RegisterProxy.SsoInfoSync" => "native-partial",
            "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat" => "native-partial",
            "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey" => "manual-state",
            "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess" => "manual-state",
            _ => null
        };

        if (expected != null && result.NativeTier != expected)
        {
            throw new InvalidOperationException($"Unexpected SignServer native_tier for {command}: {result.NativeTier}, expected {expected}");
        }

        if (SignProvider.IsRoutedOnlineCommand(command) && !SignProvider.CanReplaceWithNativeBody(command, result.NativeBody))
        {
            throw new InvalidOperationException(
                $"Unexpected SignServer native_body length for {command}: {result.NativeBody?.Length ?? 0}");
        }
    }

    private static string? TryGetString(JsonElement element, string property)
        => element.TryGetProperty(property, out var value) && value.ValueKind != JsonValueKind.Null
            ? value.GetString()
            : null;

    private static IReadOnlyList<SignStateUpdate> ParseStateUpdates(JsonElement valueJson)
    {
        if (!valueJson.TryGetProperty("state_updates", out var updates) || updates.ValueKind != JsonValueKind.Array)
        {
            return Array.Empty<SignStateUpdate>();
        }

        var result = new List<SignStateUpdate>();
        foreach (var update in updates.EnumerateArray())
        {
            result.Add(new SignStateUpdate
            {
                Kind = TryGetString(update, "kind"),
                Len = update.TryGetProperty("len", out var len) && len.TryGetInt32(out int parsedLen) ? parsedLen : null,
                Sha256_16 = TryGetString(update, "sha256_16")
            });
        }

        return result;
    }

    private static JsonObject BuildTransInfoMetadata(object? reserveFields)
    {
        var output = new JsonObject();
        if (reserveFields == null) return output;

        var transInfoProperty = reserveFields.GetType().GetProperty("TransInfo");
        if (transInfoProperty?.GetValue(reserveFields) is not IDictionary<string, string> transInfo) return output;

        foreach (var (key, value) in transInfo)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            output[key] = new JsonObject
            {
                { "len", bytes.Length },
                { "sha256_16", Sha256_16(bytes) }
            };
        }

        return output;
    }

    private void UpdateProfileState(SignServerProfile profile, object? reserveFields, byte[] reserveField)
    {
        profile.OnlineState.RegisterContext = new SignServerStateHash
        {
            Len = reserveField.Length,
            Sha256_16 = Sha256_16(reserveField)
        };

        var transInfoProperty = reserveFields?.GetType().GetProperty("TransInfo");
        if (transInfoProperty?.GetValue(reserveFields) is IDictionary<string, string> transInfo)
        {
            foreach (var (key, value) in transInfo)
            {
                var bytes = Encoding.UTF8.GetBytes(value);
                profile.OnlineState.TransInfo[key] = new SignServerStateHash
                {
                    Len = bytes.Length,
                    Sha256_16 = Sha256_16(bytes)
                };
            }
        }

        _profileStore.Save(profile);
    }

    private static string Sha256_16(byte[] bytes)
        => bytes.Length == 0 ? "" : Convert.ToHexString(SHA256.HashData(bytes))[..16];
}
