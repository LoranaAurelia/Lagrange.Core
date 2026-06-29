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

    public override bool UseNativeBodyForOnline => false;

    public override bool StrictNativeTier => _strictNativeTier || _mode == "strict";

    public override bool ShouldUseNativeBody(string command, SignResult result) =>
        SignProvider.IsRoutedNativeBodyCommand(command) &&
        result.NativeBody is { Length: > 0 };

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
        if (_advancedMode) FetchRuntimeManifest();
    }

    public override byte[]? Sign(string cmd, uint seq, byte[] body, [UnscopedRef] out byte[]? e, [UnscopedRef] out string? t)
    {
        e = null;
        t = null;

        if (!WhiteListCommand.Contains(cmd)) return null;
        if (_signServer == null) throw new Exception("Sign server is not configured");

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
            if (SignProvider.IsRoutedNativeBodyCommand(context.Command))
            {
                throw new InvalidOperationException($"{context.Command} requires an advanced SignServer native_body route");
            }

            return SendSignRequest(context.Command, context.Sequence, context.Body, context, true);
        }

        try
        {
            var routed = SendSignRequest(context.Command, context.Sequence, context.Body, context, false, route);
            LogSignResult(context.Command, context.Sequence, context.Body, routed, route);
            EnforceTier(context.Command, routed.NativeTier);
            EnforceRoutedBodyRules(context.Command, routed);
            return routed;
        }
        catch (Exception e) when (!StrictNativeTier)
        {
            if (SignProvider.IsRoutedNativeBodyCommand(context.Command))
            {
                throw;
            }

            _logger.LogWarning(e, "Routed SignServer endpoint failed for {Command}, falling back to legacy signing", context.Command);
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
            UpdateProfileState(profile, context.Command, context.Sequence, context.Payload, context.ReserveFields, context.ReserveField);
            if (!IsTrackedStatePushCommand(context.Command)) return;

            bool includeRawHex = _configuration.GetValue("SignServer:IncludeRawStatePushHex", false);
            var statePush = new JsonObject
            {
                { "command", context.Command },
                { "seq", context.Sequence },
                { "payload_len", context.Payload.Length },
                { "payload_sha256_16", BuildHashSummary(context.Payload) },
                { "reserve_hex", includeRawHex ? Convert.ToHexString(context.ReserveField) : "" },
                { "pb_extra_hex", "" },
                { "register_context_hex", includeRawHex ? profile.OnlineState.RegisterContextHex : "" },
                { "secure_hex", "" },
                { "heartbeat_hex", "" },
                { "reserve_len", context.ReserveField.Length },
                { "reserve_sha256_16", reserveHash },
                { "transinfo", BuildTransInfoMetadata(context.ReserveFields, profile, includeRawHex) },
                { "summary", BuildPushSummary(context.Command, context.Payload, profile) }
            };

            var requestJson = BuildRequestContext(
                profile,
                context.Keystore.Uin,
                context.Sequence,
                context.Payload,
                context.Command,
                metadata: null,
                includeContextHandles: true);
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
            if (response.IsSuccessStatusCode)
            {
                var json = JsonDocument.Parse(response.Content.ReadAsStream()).RootElement;
                if (TryApplyOnlineStateFromResponse(profile, json)) _profileStore.Save(profile);
            }
            else
            {
                _logger.LogDebug("SignServer state push returned {StatusCode}", response.StatusCode);
            }
        }
        catch (Exception e)
        {
            _logger.LogDebug(e, "SignServer state push failed");
        }
    }

    private static bool IsTrackedStatePushCommand(string command) => command is
        "trpc.msg.register_proxy.RegisterProxy.PushParams" or
        "trpc.msg.register_proxy.RegisterProxy.InfoSyncPush" or
        "ConfigPushSvc.PushReq";

    private SignResult SendSignRequest(string cmd, uint seq, byte[] body, SignRequestContext? context, bool legacy, string? route = null)
    {
        var profile = _profileStore.GetProfile();
        var requestJson = BuildRequestContext(
            profile,
            context?.Keystore.Uin ?? 0,
            seq,
            body,
            legacy ? cmd : null,
            cmd,
            context?.Metadata,
            includeContextHandles: route != null);
        string endpoint = route == null ? _signServer! : $"{_signServer!.TrimEnd('/')}/{route}";
        using var request = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri(endpoint),
            Content = JsonContent.Create(requestJson)
        };

        using var message = _client.Send(request);
        if (message.StatusCode != HttpStatusCode.OK)
        {
            string responseBody = message.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            string detail = string.IsNullOrWhiteSpace(responseBody) ? "" : $": {TrimForLog(responseBody, 512)}";
            throw new Exception($"Signer server returned a {message.StatusCode}{detail}");
        }
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
        bool stateChanged = TryApplyOnlineStateFromResponse(profile, json);
        if (cmd == "trpc.msg.register_proxy.RegisterProxy.SsoInfoSync")
        {
            profile.OnlineState.LastSsoInfoSyncSeq = seq;
            stateChanged = true;
        }
        if (cmd == "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat")
        {
            profile.OnlineState.HeartbeatCounter++;
            profile.OnlineState.LastHeartbeatSeq = seq;
            stateChanged = true;
        }
        if (!string.IsNullOrEmpty(result.NativeTier))
        {
            profile.OnlineState.LastNativeTiers[cmd] = result.NativeTier;
            stateChanged = true;
        }

        if (stateChanged) _profileStore.Save(profile);

        return result;
    }

    private JsonObject BuildRequestContext(
        SignServerProfile profile,
        uint uin,
        uint seq,
        byte[] body,
        string? cmd,
        string? command = null,
        IReadOnlyDictionary<string, object>? metadata = null,
        bool includeContextHandles = false)
    {
        if (uin != 0 && profile.Identity.Uin != uin.ToString())
        {
            profile.Identity.Uin = uin.ToString();
            EnsureQimei(profile);
            _profileStore.Save(profile);
        }
        else
        {
            EnsureQimei(profile);
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
            { "qimei36", profile.Identity.Qimei36 },
            { "env_id_str", profile.Environment.EnvIdStr },
            { "fake_hostname", environment.FakeHostname },
            { "fake_proc_comm", environment.FakeProcComm },
            { "fake_proc_cmdline", environment.FakeProcCmdline },
            { "fake_device_name", environment.FakeDeviceName },
            { "fake_hardware_model", environment.FakeHardwareModel },
            { "fake_os_release", environment.FakeOsRelease },
            { "fake_timezone", environment.FakeTimezone },
            { "device_profile", BuildDeviceProfile(profile) },
            { "profile", BuildProfileSummary(profile) },
            { "online_state", BuildOnlineState(profile, _configuration.GetValue("SignServer:IncludeRawStatePushHex", false)) }
        };

        if (cmd != null) request["cmd"] = cmd;
        if (includeContextHandles) request["context_handles"] = BuildContextHandles(profile);
        if (command == "trpc.msg.register_proxy.RegisterProxy.SsoInfoSync")
        {
            request["sso_info_sync_source"] = new JsonObject
            {
                { "body_hex", Convert.ToHexString(body) }
            };
        }
        if (command == "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat")
        {
            bool buildMinimalBody = _configuration.GetValue("SignServer:HeartbeatBuildMinimalBody", false);
            request["heartbeat_source"] = buildMinimalBody
                ? new JsonObject
                {
                    { "build_minimal_body", true },
                    { "heartbeat_type", 1 }
                }
                : new JsonObject
                {
                    { "body_hex", Convert.ToHexString(body) },
                    { "heartbeat_type", 1 }
                };
        }
        if (SignProvider.IsRoutedSecureCommand(command ?? ""))
        {
            request["secure_access_source"] = new JsonObject
            {
                { "body_hex", Convert.ToHexString(body) }
            };
        }
        if (command == "OidbSvcTrpcTcp.0x102a_0" && TryGetDomains(metadata, out var domains))
        {
            var domainArray = new JsonArray();
            foreach (var domain in domains) domainArray.Add(domain);
            request["oidb102a_source"] = new JsonObject { { "domains", domainArray } };
        }
        if (command == "trpc.o3.report.Report.SsoReport")
        {
            request["sso_report_source"] = JsonSerializer.SerializeToNode(profile.SsoReportSource);
        }

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
            TokenLength = string.IsNullOrEmpty(token) ? 0 : Convert.FromHexString(token).Length,
            NativeBody = string.IsNullOrEmpty(nativeBody) ? null : Convert.FromHexString(nativeBody),
            NativeTier = nativeTier,
            StateUpdates = ParseStateUpdates(valueJson),
            Diagnostic = valueJson.TryGetProperty("diagnostic", out var diagnostic) ? diagnostic.GetRawText() : null,
            ExtraFields = valueJson.TryGetProperty("extra_fields", out var extraFields) ? extraFields.GetRawText() : null
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

    private void FetchRuntimeManifest()
    {
        try
        {
            var profile = _profileStore.GetProfile();
            if (profile.RuntimeManifest?.Version == version && profile.RuntimeManifest.Length > 0) return;

            using var request = new HttpRequestMessage(HttpMethod.Get, $"{_signServer!.TrimEnd('/')}/runtime-manifest");
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(
                _configuration.GetValue("SignServer:AdvancedProbeTimeoutMs", 1500)));
            using var response = _client.Send(request, cts.Token);
            if (!response.IsSuccessStatusCode) return;

            string text = response.Content.ReadAsStringAsync(cts.Token).GetAwaiter().GetResult();
            profile.RuntimeManifest = new SignServerRuntimeManifestCache
            {
                Version = version,
                FetchedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                Length = text.Length,
                Sha256_16 = Sha256_16(Encoding.UTF8.GetBytes(text))
            };
            _profileStore.Save(profile);
        }
        catch (Exception e)
        {
            _logger.LogDebug(e, "SignServer runtime-manifest fetch failed");
        }
    }

    private static string? GetRoutedEndpoint(string command) => command switch
    {
        "trpc.msg.register_proxy.RegisterProxy.SsoInfoSync" => "online/sso-info-sync",
        "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat" => "online/heartbeat",
        "trpc.qq_new_tech.status_svc.StatusService.Register" => "online/status-register",
        "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey" => "secure/establish-share-key",
        "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess" => "secure/secure-access",
        "trpc.o3.report.Report.SsoReport" => "report/sso-report",
        "OidbSvcTrpcTcp.0x102a_1" => "oidb/102a/client-key",
        "OidbSvcTrpcTcp.0x102a_0" => "oidb/102a/cookies",
        _ => null
    };

    private void LogSignResult(string command, uint seq, byte[] body, SignResult result, string endpoint)
    {
        var diagnostic = TryParseJson(result.Diagnostic);
        var extraFields = TryParseJson(result.ExtraFields);
        var diagnosticCmd = TryGetNestedString(diagnostic, "cmd") ?? command;
        var diagnosticSrcLen = TryGetNestedInt(diagnostic, "src_len");
        var diagnosticNativeBodyLen = TryGetNestedInt(diagnostic, "native_body_len");
        var ssoReportBodyHash = TryGetNestedString(extraFields, "sso_report", "body_sha256_16") ?? "";
        var calledRvas = TryGetRawProperty(diagnostic, "called_rvas") ?? "";
        var stateUpdates = result.StateUpdates.Count == 0
            ? ""
            : string.Join(",", result.StateUpdates.Select(update => $"{update.Kind}:{update.Len}:{update.Sha256_16}"));

        _logger.LogInformation(
            "SignServer routed command={Command} diagnostic_cmd={DiagnosticCommand} endpoint={Endpoint} seq={Sequence} body_len={BodyLen} body_sha256_16={BodyHash} native_tier={NativeTier} native_body_len={NativeBodyLen} diagnostic_src_len={DiagnosticSrcLen} diagnostic_native_body_len={DiagnosticNativeBodyLen} sso_report_body_sha256_16={SsoReportBodyHash} sign_len={SignLen} token_len={TokenLen} extra_len={ExtraLen} called_rvas={CalledRvas} state_updates={StateUpdates}",
            command,
            diagnosticCmd,
            endpoint,
            seq,
            body.Length,
            Sha256_16(body),
            result.NativeTier ?? "",
            result.NativeBody?.Length ?? 0,
            diagnosticSrcLen,
            diagnosticNativeBodyLen,
            ssoReportBodyHash,
            result.Sign?.Length ?? 0,
            result.TokenLength ?? result.Token?.Length ?? 0,
            result.Extra?.Length ?? 0,
            calledRvas,
            stateUpdates);

        if (SignProvider.IsRoutedReportCommand(command) && (result.Extra == null || result.Extra.Length == 0))
        {
            _logger.LogDebug("SignServer SsoReport returned empty extra; QUA extra fallback was expected");
        }
    }

    private void EnforceTier(string command, string? nativeTier)
    {
        if (!StrictNativeTier) return;

        string? expected = command switch
        {
            "trpc.msg.register_proxy.RegisterProxy.SsoInfoSync" => "online-sign",
            "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat" => "online-sign",
            "trpc.qq_new_tech.status_svc.StatusService.Register" => "online-sign",
            "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey" => "manual-state",
            "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess" => "manual-state",
            "trpc.o3.report.Report.SsoReport" => "pure-calc-body",
            "OidbSvcTrpcTcp.0x102a_1" => "pure-calc-body",
            "OidbSvcTrpcTcp.0x102a_0" => "pure-calc-body",
            _ => null
        };

        if (expected != null && nativeTier != expected)
        {
            throw new InvalidOperationException($"Unexpected SignServer native_tier for {command}: {nativeTier}, expected {expected}");
        }
    }

    private static void EnforceRoutedBodyRules(string command, SignResult result)
    {
        if (!SignProvider.IsRoutedNativeBodyCommand(command)) return;

        if (SignProvider.IsRoutedReportCommand(command) && result.NativeTier != "pure-calc-body")
        {
            throw new InvalidOperationException($"Unexpected SignServer native_tier for {command}: {result.NativeTier}, expected pure-calc-body");
        }

        if (result.NativeBody is not { Length: > 0 })
        {
            throw new InvalidOperationException($"SignServer {command} did not return native_body");
        }
    }

    private static bool TryGetDomains(IReadOnlyDictionary<string, object>? metadata, out IEnumerable<string> domains)
    {
        domains = Array.Empty<string>();
        if (metadata == null || !metadata.TryGetValue("oidb102a_domains", out var value)) return false;
        if (value is IEnumerable<string> domainList)
        {
            domains = domainList;
            return true;
        }

        return false;
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
            int? length = null;
            if (update.TryGetProperty("length", out var lengthJson) && lengthJson.TryGetInt32(out int parsedLength))
            {
                length = parsedLength;
            }
            else if (update.TryGetProperty("len", out var lenJson) && lenJson.TryGetInt32(out int parsedLen))
            {
                length = parsedLen;
            }

            result.Add(new SignStateUpdate
            {
                Kind = TryGetString(update, "kind"),
                Len = length,
                Sha256_16 = TryGetString(update, "sha256_16")
            });
        }

        return result;
    }

    private static JsonObject BuildContextHandles(SignServerProfile profile)
    {
        var transInfo = new JsonObject();
        foreach (var (key, value) in profile.OnlineState.TransInfo) transInfo[key] = BuildHashSummary(value);

        return new JsonObject
        {
            { "register_context", BuildHashSummary(profile.OnlineState.RegisterContext) },
            { "transinfo", transInfo },
            { "secure", BuildHashSummary(profile.SecureState.LastReserve) },
            { "heartbeat", BuildHashSummary(Array.Empty<byte>()) }
        };
    }

    private static JsonObject BuildDeviceProfile(SignServerProfile profile)
    {
        var environment = profile.Environment;
        return new JsonObject
        {
            { "hostname", environment.Hostname },
            { "device_name", environment.DeviceName },
            { "distro", environment.Distro },
            { "kernel", environment.Kernel },
            { "desktop_env", environment.DesktopEnv },
            { "session_type", environment.SessionType },
            { "vendor", environment.Vendor },
            { "model", environment.Model },
            { "fake_hostname", environment.FakeHostname },
            { "fake_proc_comm", environment.FakeProcComm },
            { "fake_proc_cmdline", environment.FakeProcCmdline },
            { "fake_device_name", environment.FakeDeviceName },
            { "fake_hardware_model", environment.FakeHardwareModel },
            { "fake_os_release", environment.FakeOsRelease },
            { "fake_timezone", environment.FakeTimezone },
            { "locale_id", environment.LocaleId },
            { "env_id_str", environment.EnvIdStr },
            { "is_test_env", environment.IsTestEnv },
            { "canary", environment.Canary }
        };
    }

    private static JsonObject BuildProfileSummary(SignServerProfile profile)
    {
        return new JsonObject
        {
            { "schema_version", profile.SchemaVersion },
            { "profile_id", profile.ProfileId },
            { "wrapper_version", profile.WrapperVersion },
            { "protocol", profile.Protocol },
            { "created_at_unix", profile.CreatedAtUnix },
            { "guid_hash", HashString(profile.Identity.Guid) },
            { "machine_id", profile.Identity.MachineId },
            { "qimei36_hash", HashString(profile.Identity.Qimei36) },
            { "qimei36_len", profile.Identity.Qimei36.Length }
        };
    }

    private static JsonObject BuildOnlineState(SignServerProfile profile, bool includeRaw)
    {
        var state = profile.OnlineState;
        var variantCounts = new JsonObject();
        foreach (var (key, value) in state.InfoSyncPushVariantCounts) variantCounts[key] = value;

        var transInfo = new JsonObject();
        foreach (var (key, value) in state.TransInfo) transInfo[key] = BuildHashSummary(value);

        var output = new JsonObject
        {
            { "online_push_flags", state.OnlinePushFlags },
            { "heartbeat_counter", state.HeartbeatCounter },
            { "last_push_command", state.LastPushCommand },
            { "last_push_branch", state.LastPushBranch },
            { "last_push_field1", state.LastPushField1 },
            { "push_params_count", state.PushParamsCount },
            { "push_params_last_field1", state.PushParamsLastField1 },
            { "push_params_last_hash", state.PushParamsLastHash },
            { "info_sync_push_count", state.InfoSyncPushCount },
            { "info_sync_push_variant_counts", variantCounts },
            { "info_sync_push_last_field3", state.InfoSyncPushLastField3 },
            { "info_sync_push_last_field4", state.InfoSyncPushLastField4 },
            { "info_sync_push_last_hash", state.InfoSyncPushLastHash },
            { "config_push_count", state.ConfigPushCount },
            { "config_push_last_hash", state.ConfigPushLastHash },
            { "msf_login_notify_count", state.MsfLoginNotifyCount },
            { "msf_login_notify_last_hash", state.MsfLoginNotifyLastHash },
            { "last_sso_info_sync_seq", state.LastSsoInfoSyncSeq },
            { "last_heartbeat_seq", state.LastHeartbeatSeq },
            { "transinfo", transInfo },
            { "register_context", BuildHashSummary(state.RegisterContext) }
        };

        if (includeRaw)
        {
            var transInfoValues = new JsonObject();
            foreach (var (key, value) in state.TransInfoValues) transInfoValues[key] = value;
            output["transinfo_values"] = transInfoValues;
            output["register_context_hex"] = state.RegisterContextHex;
        }

        return output;
    }

    private static JsonObject BuildTransInfoMetadata(object? reserveFields, SignServerProfile profile, bool includeRaw)
    {
        var output = new JsonObject();
        foreach (var (key, value) in profile.OnlineState.TransInfoValues)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            output[key] = includeRaw
                ? value
                : BuildHashSummary(bytes);
        }

        if (reserveFields == null) return output;

        var transInfoProperty = reserveFields.GetType().GetProperty("TransInfo");
        if (transInfoProperty?.GetValue(reserveFields) is not IDictionary<string, string> transInfo) return output;

        foreach (var (key, value) in transInfo)
        {
            var bytes = Encoding.UTF8.GetBytes(value);
            output[key] = includeRaw
                ? value
                : BuildHashSummary(bytes);
            profile.OnlineState.TransInfoValues[key] = value;
            profile.OnlineState.TransInfo[key] = new SignServerStateHash { Len = bytes.Length, Sha256_16 = Sha256_16(bytes) };
        }

        return output;
    }

    private static JsonObject BuildPushSummary(string command, byte[] payload, SignServerProfile profile)
    {
        var payloadHash = Sha256_16(payload);
        var summary = new JsonObject
        {
            { "command", command },
            { "payload_len", payload.Length },
            { "payload_sha256_16", payloadHash }
        };

        var fields = ReadTopLevelFields(payload);
        if (fields.Count != 0)
        {
            var fieldCounts = new JsonObject();
            foreach (var group in fields.GroupBy(field => field))
            {
                fieldCounts[group.Key.ToString()] = group.Count();
            }

            summary["top_level_field_counts"] = fieldCounts;
        }

        switch (command)
        {
            case "trpc.msg.register_proxy.RegisterProxy.PushParams":
                profile.OnlineState.PushParamsCount++;
                profile.OnlineState.PushParamsLastHash = payloadHash;
                profile.OnlineState.PushParamsLastField1 = fields.Contains(1) ? "present" : null;
                summary["field1"] = profile.OnlineState.PushParamsLastField1 ?? "";
                break;
            case "trpc.msg.register_proxy.RegisterProxy.InfoSyncPush":
                profile.OnlineState.InfoSyncPushCount++;
                profile.OnlineState.InfoSyncPushLastHash = payloadHash;
                profile.OnlineState.InfoSyncPushLastField3 = fields.Contains(3) ? "present" : null;
                profile.OnlineState.InfoSyncPushLastField4 = fields.Contains(4) ? "present" : null;
                foreach (var field in fields)
                {
                    var key = $"field{field}";
                    profile.OnlineState.InfoSyncPushVariantCounts[key] =
                        profile.OnlineState.InfoSyncPushVariantCounts.GetValueOrDefault(key) + 1;
                }

                summary["field3"] = profile.OnlineState.InfoSyncPushLastField3 ?? "";
                summary["field4"] = profile.OnlineState.InfoSyncPushLastField4 ?? "";
                break;
            case "ConfigPushSvc.PushReq":
                profile.OnlineState.ConfigPushCount++;
                profile.OnlineState.ConfigPushLastHash = payloadHash;
                break;
        }

        if (command is "trpc.msg.register_proxy.RegisterProxy.PushParams" or
            "trpc.msg.register_proxy.RegisterProxy.InfoSyncPush" or
            "ConfigPushSvc.PushReq")
        {
            profile.OnlineState.LastPushCommand = command;
        }

        return summary;
    }

    private static JsonObject BuildHashSummary(byte[] bytes) => new()
    {
        { "length", bytes.Length },
        { "sha256_16", Sha256_16(bytes) }
    };

    private static JsonObject BuildHashSummary(SignServerStateHash hash) => new()
    {
        { "length", hash.Len },
        { "sha256_16", hash.Sha256_16 }
    };

    private static List<int> ReadTopLevelFields(byte[] payload)
    {
        var fields = new List<int>();
        int offset = 0;
        while (offset < payload.Length)
        {
            if (!TryReadVarint(payload, ref offset, out ulong key)) break;
            int fieldNumber = (int)(key >> 3);
            int wireType = (int)(key & 0x07);
            if (fieldNumber <= 0) break;
            fields.Add(fieldNumber);

            switch (wireType)
            {
                case 0:
                    if (!TryReadVarint(payload, ref offset, out _)) return fields;
                    break;
                case 1:
                    offset += 8;
                    break;
                case 2:
                    if (!TryReadVarint(payload, ref offset, out ulong length)) return fields;
                    offset += checked((int)length);
                    break;
                case 5:
                    offset += 4;
                    break;
                default:
                    return fields;
            }

            if (offset > payload.Length) break;
        }

        return fields;
    }

    private static bool TryReadVarint(byte[] bytes, ref int offset, out ulong value)
    {
        value = 0;
        int shift = 0;
        while (offset < bytes.Length && shift < 64)
        {
            byte current = bytes[offset++];
            value |= (ulong)(current & 0x7f) << shift;
            if ((current & 0x80) == 0) return true;
            shift += 7;
        }

        return false;
    }

    private static void EnsureQimei(SignServerProfile profile)
    {
        if (!string.IsNullOrWhiteSpace(profile.Identity.Qimei36) &&
            profile.Identity.Qimei36Uin == profile.Identity.Uin)
        {
            return;
        }

        if (!Guid.TryParse(profile.Identity.Guid, out var guid)) return;

        profile.Identity.Qimei36 = SignServerProfile.GenerateQimei36(
            string.IsNullOrWhiteSpace(profile.ProfileId) ? profile.Identity.Session : profile.ProfileId,
            profile.Identity.Uin,
            guid);
        profile.Identity.Qimei36Uin = profile.Identity.Uin;
    }

    private void UpdateProfileState(
        SignServerProfile profile,
        string command,
        uint sequence,
        byte[] payload,
        object? reserveFields,
        byte[] reserveField)
    {
        if (SignProvider.IsRoutedSecureCommand(command))
        {
            profile.SecureState.LastCommand = command;
            profile.SecureState.LastSeq = sequence;
            profile.SecureState.LastPayload = new SignServerStateHash
            {
                Len = payload.Length,
                Sha256_16 = Sha256_16(payload)
            };
            profile.SecureState.LastReserve = new SignServerStateHash
            {
                Len = reserveField.Length,
                Sha256_16 = Sha256_16(reserveField)
            };
            if (command == "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey") profile.SecureState.EstablishCount++;
            if (command == "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess") profile.SecureState.SecureAccessCount++;
        }

        if (SignProvider.IsRoutedOidb102ACommand(command))
        {
            profile.Oidb102AState.LastCommand = command;
            profile.Oidb102AState.LastSeq = sequence;
            profile.Oidb102AState.LastResponse = new SignServerStateHash
            {
                Len = payload.Length,
                Sha256_16 = Sha256_16(payload)
            };
            if (command == "OidbSvcTrpcTcp.0x102a_1") profile.Oidb102AState.ClientKeyResponseCount++;
            if (command == "OidbSvcTrpcTcp.0x102a_0") profile.Oidb102AState.CookieResponseCount++;
        }

        if (reserveField.Length > 0)
        {
            profile.OnlineState.RegisterContext = new SignServerStateHash
            {
                Len = reserveField.Length,
                Sha256_16 = Sha256_16(reserveField)
            };
            profile.OnlineState.RegisterContextHex = _configuration.GetValue("SignServer:IncludeRawStatePushHex", false)
                ? Convert.ToHexString(reserveField)
                : "";
        }

        var transInfoProperty = reserveFields?.GetType().GetProperty("TransInfo");
        if (transInfoProperty?.GetValue(reserveFields) is IDictionary<string, string> transInfo)
        {
            bool includeRawHex = _configuration.GetValue("SignServer:IncludeRawStatePushHex", false);
            foreach (var (key, value) in transInfo)
            {
                var bytes = Encoding.UTF8.GetBytes(value);
                profile.OnlineState.TransInfo[key] = new SignServerStateHash
                {
                    Len = bytes.Length,
                    Sha256_16 = Sha256_16(bytes)
                };
                if (includeRawHex) profile.OnlineState.TransInfoValues[key] = value;
                else profile.OnlineState.TransInfoValues.Remove(key);
            }
        }

        _profileStore.Save(profile);
    }

    private static string Sha256_16(byte[] bytes)
        => bytes.Length == 0 ? "" : Convert.ToHexString(SHA256.HashData(bytes))[..16];

    private static string HashString(string value)
        => string.IsNullOrEmpty(value) ? "" : Sha256_16(Encoding.UTF8.GetBytes(value));

    private static string TrimForLog(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];

    private static JsonElement? TryParseJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;

        try
        {
            using var document = JsonDocument.Parse(json);
            return document.RootElement.Clone();
        }
        catch
        {
            return null;
        }
    }

    private static string? TryGetNestedString(JsonElement? element, params string[] path)
    {
        if (!TryGetNestedElement(element, out var value, path)) return null;
        return value.ValueKind == JsonValueKind.String ? value.GetString() : value.GetRawText();
    }

    private static int? TryGetNestedInt(JsonElement? element, params string[] path)
    {
        if (!TryGetNestedElement(element, out var value, path)) return null;
        return value.TryGetInt32(out int result) ? result : null;
    }

    private static string? TryGetRawProperty(JsonElement? element, string property)
    {
        if (element == null || element.Value.ValueKind != JsonValueKind.Object) return null;
        return element.Value.TryGetProperty(property, out var value) ? value.GetRawText() : null;
    }

    private static bool TryGetNestedElement(JsonElement? element, out JsonElement value, params string[] path)
    {
        value = default;
        if (element == null) return false;

        value = element.Value;
        foreach (var part in path)
        {
            if (value.ValueKind != JsonValueKind.Object || !value.TryGetProperty(part, out value)) return false;
        }

        return true;
    }

    private static bool TryApplyOnlineStateFromResponse(SignServerProfile profile, JsonElement json)
    {
        if (!TryFindOnlineState(json, out var onlineStateJson)) return false;

        try
        {
            var incoming = onlineStateJson.Deserialize<SignServerOnlineState>();
            if (incoming == null) return false;

            MergeOnlineState(profile.OnlineState, incoming);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryFindOnlineState(JsonElement json, out JsonElement onlineState)
    {
        onlineState = default;
        if (!json.TryGetProperty("value", out var value)) return false;

        if (value.TryGetProperty("extra_fields", out var extraFields))
        {
            if (extraFields.TryGetProperty("state_push", out var statePush) &&
                statePush.TryGetProperty("online_state", out onlineState))
            {
                return onlineState.ValueKind == JsonValueKind.Object;
            }

            if (extraFields.TryGetProperty("online_state", out onlineState))
            {
                return onlineState.ValueKind == JsonValueKind.Object;
            }
        }

        if (value.TryGetProperty("online_state", out onlineState))
        {
            return onlineState.ValueKind == JsonValueKind.Object;
        }

        return false;
    }

    private static void MergeOnlineState(SignServerOnlineState target, SignServerOnlineState incoming)
    {
        target.OnlinePushFlags |= incoming.OnlinePushFlags;
        target.HeartbeatCounter = Math.Max(target.HeartbeatCounter, incoming.HeartbeatCounter);
        target.PushParamsCount = Math.Max(target.PushParamsCount, incoming.PushParamsCount);
        target.InfoSyncPushCount = Math.Max(target.InfoSyncPushCount, incoming.InfoSyncPushCount);
        target.ConfigPushCount = Math.Max(target.ConfigPushCount, incoming.ConfigPushCount);
        target.MsfLoginNotifyCount = Math.Max(target.MsfLoginNotifyCount, incoming.MsfLoginNotifyCount);

        target.LastPushCommand = incoming.LastPushCommand ?? target.LastPushCommand;
        target.LastPushBranch = incoming.LastPushBranch ?? target.LastPushBranch;
        target.LastPushField1 = incoming.LastPushField1 ?? target.LastPushField1;
        target.PushParamsLastField1 = incoming.PushParamsLastField1 ?? target.PushParamsLastField1;
        target.PushParamsLastHash = incoming.PushParamsLastHash ?? target.PushParamsLastHash;
        target.InfoSyncPushLastField3 = incoming.InfoSyncPushLastField3 ?? target.InfoSyncPushLastField3;
        target.InfoSyncPushLastField4 = incoming.InfoSyncPushLastField4 ?? target.InfoSyncPushLastField4;
        target.InfoSyncPushLastHash = incoming.InfoSyncPushLastHash ?? target.InfoSyncPushLastHash;
        target.ConfigPushLastHash = incoming.ConfigPushLastHash ?? target.ConfigPushLastHash;
        target.MsfLoginNotifyLastHash = incoming.MsfLoginNotifyLastHash ?? target.MsfLoginNotifyLastHash;

        foreach (var (key, value) in incoming.InfoSyncPushVariantCounts)
        {
            target.InfoSyncPushVariantCounts[key] = Math.Max(
                target.InfoSyncPushVariantCounts.GetValueOrDefault(key),
                value);
        }
    }
}
