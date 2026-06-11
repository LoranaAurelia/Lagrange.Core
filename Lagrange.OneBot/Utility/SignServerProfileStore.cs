using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Lagrange.Core.Common;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Lagrange.OneBot.Utility;

public sealed class SignServerProfileStore
{
    private readonly IConfiguration _configuration;

    private readonly ILogger<SignServerProfileStore> _logger;

    private readonly object _lock = new();

    private SignServerProfile? _profile;

    private string ProfilePath => _configuration["ConfigPath:SignServerProfile"] ?? "signserver-profile.json";

    public SignServerProfileStore(IConfiguration configuration, ILogger<SignServerProfileStore> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public SignServerProfile GetProfile(string wrapperVersion = "49738")
    {
        lock (_lock)
        {
            if (_profile != null) return _profile;

            if (File.Exists(ProfilePath))
            {
                try
                {
                    _profile = JsonSerializer.Deserialize<SignServerProfile>(File.ReadAllText(ProfilePath));
                }
                catch (Exception e)
                {
                    _logger.LogWarning(e, "Failed to read SignServer synthetic profile, generating a new one");
                }
            }

            _profile ??= SignServerProfile.Create(wrapperVersion);
            Save(_profile);
            return _profile;
        }
    }

    public BotDeviceInfo BuildDeviceInfo(BotDeviceInfo? existing = null)
    {
        var profile = GetProfile();
        var identity = profile.Identity;
        var environment = profile.Environment;

        return new BotDeviceInfo
        {
            Guid = Guid.Parse(identity.Guid),
            MacAddress = ParseMac(identity.MacAddress),
            DeviceName = environment.FakeDeviceName,
            SystemKernel = environment.FakeOsRelease.Split(" x86_64", StringSplitOptions.None)[0],
            KernelVersion = environment.FakeOsRelease.Replace("Linux ", "").Replace(" x86_64", "")
        };
    }

    public void Save(SignServerProfile profile)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(ProfilePath));
        if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

        File.WriteAllText(ProfilePath, JsonSerializer.Serialize(profile, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
    }

    private static byte[] ParseMac(string mac)
        => mac.Split(':').Select(part => Convert.ToByte(part, 16)).ToArray();
}

public sealed class SignServerProfile
{
    [JsonPropertyName("schema_version")] public int SchemaVersion { get; set; } = 1;

    [JsonPropertyName("profile_id")] public string ProfileId { get; set; } = "";

    [JsonPropertyName("created_at_unix")] public long CreatedAtUnix { get; set; }

    [JsonPropertyName("wrapper_version")] public string WrapperVersion { get; set; } = "49738";

    [JsonPropertyName("protocol")] public string Protocol { get; set; } = "Linux";

    [JsonPropertyName("app")] public SignServerProfileApp App { get; set; } = new();

    [JsonPropertyName("identity")] public SignServerProfileIdentity Identity { get; set; } = new();

    [JsonPropertyName("environment")] public SignServerProfileEnvironment Environment { get; set; } = new();

    [JsonPropertyName("online_state")] public SignServerOnlineState OnlineState { get; set; } = new();

    public static SignServerProfile Create(string wrapperVersion)
    {
        var guidBytes = RandomNumberGenerator.GetBytes(16);
        var guid = new Guid(guidBytes);
        var machineId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var mac = $"02:{machineId[0..2]}:{machineId[2..4]}:{machineId[4..6]}:{machineId[6..8]}:{machineId[8..10]}";
        var sessionSuffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();

        return new SignServerProfile
        {
            ProfileId = $"lagrange-{wrapperVersion}-profile-{sessionSuffix}",
            CreatedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            WrapperVersion = wrapperVersion,
            App = new SignServerProfileApp(),
            Identity = new SignServerProfileIdentity
            {
                Session = $"lagrange-{wrapperVersion}-profile-{sessionSuffix}",
                Guid = guid.ToString(),
                MachineId = machineId,
                MacAddress = mac
            },
            Environment = new SignServerProfileEnvironment()
        };
    }
}

public sealed class SignServerProfileApp
{
    [JsonPropertyName("qua")] public string Qua { get; set; } = "V1_LNX_NQ_3.2.29_49738_GW_B";

    [JsonPropertyName("current_version")] public string CurrentVersion { get; set; } = "3.2.29-49738";

    [JsonPropertyName("platform")] public string Platform { get; set; } = "Linux";
}

public sealed class SignServerProfileIdentity
{
    [JsonPropertyName("uin")] public string Uin { get; set; } = "0";

    [JsonPropertyName("session")] public string Session { get; set; } = "";

    [JsonPropertyName("guid")] public string Guid { get; set; } = "";

    [JsonPropertyName("machine_id")] public string MachineId { get; set; } = "";

    [JsonPropertyName("mac_address")] public string MacAddress { get; set; } = "";
}

public sealed class SignServerProfileEnvironment
{
    [JsonPropertyName("fake_hostname")] public string FakeHostname { get; set; } = "aurora-t14";

    [JsonPropertyName("fake_proc_comm")] public string FakeProcComm { get; set; } = "qq";

    [JsonPropertyName("fake_proc_cmdline")]
    public string FakeProcCmdline { get; set; } = "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService";

    [JsonPropertyName("fake_device_name")] public string FakeDeviceName { get; set; } = "ThinkPad T14 Gen 3";

    [JsonPropertyName("fake_hardware_model")] public string FakeHardwareModel { get; set; } = "Lenovo ThinkPad T14 Gen 3";

    [JsonPropertyName("fake_os_release")] public string FakeOsRelease { get; set; } = "Linux 6.8.0-60-generic x86_64";

    [JsonPropertyName("fake_timezone")] public string FakeTimezone { get; set; } = "Asia/Shanghai";

    [JsonPropertyName("locale_id")] public int LocaleId { get; set; } = 2052;

    [JsonPropertyName("vendor_name")] public string VendorName { get; set; } = "";

    [JsonPropertyName("os_lower")] public string OsLower { get; set; } = "linux";
}

public sealed class SignServerOnlineState
{
    [JsonPropertyName("last_sso_info_sync_seq")] public uint LastSsoInfoSyncSeq { get; set; }

    [JsonPropertyName("last_heartbeat_seq")] public uint LastHeartbeatSeq { get; set; }

    [JsonPropertyName("last_native_tiers")] public Dictionary<string, string> LastNativeTiers { get; set; } = new();

    [JsonPropertyName("transinfo")] public Dictionary<string, SignServerStateHash> TransInfo { get; set; } = new();

    [JsonPropertyName("register_context")] public SignServerStateHash RegisterContext { get; set; } = new();
}

public sealed class SignServerStateHash
{
    [JsonPropertyName("len")] public int Len { get; set; }

    [JsonPropertyName("sha256_16")] public string Sha256_16 { get; set; } = "";
}
