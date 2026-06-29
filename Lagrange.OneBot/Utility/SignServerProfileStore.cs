using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
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

    private string DevicePath => _configuration["ConfigPath:DeviceInfo"] ?? "device.json";

    public SignServerProfileStore(IConfiguration configuration, ILogger<SignServerProfileStore> logger)
    {
        _configuration = configuration;
        _logger = logger;
    }

    public SignServerProfile GetProfile(string wrapperVersion = "49738", BotDeviceInfo? existing = null)
    {
        lock (_lock)
        {
            if (_profile != null) return _profile;

            if (File.Exists(DevicePath))
            {
                try
                {
                    var root = JsonNode.Parse(File.ReadAllText(DevicePath))?.AsObject();
                    if (root?["sign_server_profile"] is JsonNode profileNode)
                    {
                        _profile = profileNode.Deserialize<SignServerProfile>();
                    }
                }
                catch (Exception e)
                {
                    _logger.LogWarning(e, "Failed to read SignServer synthetic profile from device file, generating a new one");
                }
            }

            existing ??= ReadDeviceInfo();
            _profile ??= SignServerProfile.Create(wrapperVersion, existing);
            Save(_profile, existing);
            return _profile;
        }
    }

    public BotDeviceInfo BuildDeviceInfo(BotDeviceInfo? existing = null)
    {
        var profile = GetProfile(existing: existing);
        var identity = profile.Identity;
        var environment = profile.Environment;

        if (!Guid.TryParse(identity.Guid, out var guid))
        {
            guid = existing?.Guid ?? Guid.NewGuid();
            identity.Guid = guid.ToString();
        }

        var macAddress = TryParseMac(identity.MacAddress) ?? existing?.MacAddress ?? RandomNumberGenerator.GetBytes(6);
        identity.MacAddress = FormatMac(macAddress);

        var device = new BotDeviceInfo
        {
            Guid = guid,
            MacAddress = macAddress,
            DeviceName = environment.FakeDeviceName,
            SystemKernel = environment.FakeOsRelease.Split(" x86_64", StringSplitOptions.None)[0],
            KernelVersion = environment.FakeOsRelease.Replace("Linux ", "").Replace(" x86_64", "")
        };

        Save(profile, device);
        return device;
    }

    public void Save(SignServerProfile profile, BotDeviceInfo? device = null)
    {
        lock (_lock)
        {
            var directory = Path.GetDirectoryName(Path.GetFullPath(DevicePath));
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);

            var root = ReadDeviceRoot(device);
            root["sign_server_profile"] = JsonSerializer.SerializeToNode(profile, JsonOptions);
            File.WriteAllText(DevicePath, root.ToJsonString(JsonOptions));
        }
    }

    public void SaveDeviceInfo(BotDeviceInfo device)
    {
        lock (_lock)
        {
            if (_profile == null)
            {
                File.WriteAllText(DevicePath, JsonSerializer.Serialize(device, JsonOptions));
                return;
            }

            Save(_profile, device);
        }
    }

    private JsonObject ReadDeviceRoot(BotDeviceInfo? device)
    {
        JsonObject? root = null;
        if (File.Exists(DevicePath))
        {
            try
            {
                root = JsonNode.Parse(File.ReadAllText(DevicePath)) as JsonObject;
            }
            catch (Exception e)
            {
                _logger.LogWarning(e, "Failed to merge SignServer synthetic profile into existing device file, rewriting it");
            }
        }

        root ??= new JsonObject();
        if (device == null) return root;

        root[nameof(BotDeviceInfo.Guid)] = device.Guid;
        root[nameof(BotDeviceInfo.MacAddress)] = JsonSerializer.SerializeToNode(device.MacAddress, JsonOptions);
        root[nameof(BotDeviceInfo.DeviceName)] = device.DeviceName;
        root[nameof(BotDeviceInfo.SystemKernel)] = device.SystemKernel;
        root[nameof(BotDeviceInfo.KernelVersion)] = device.KernelVersion;
        return root;
    }

    private BotDeviceInfo? ReadDeviceInfo()
    {
        if (!File.Exists(DevicePath)) return null;

        try
        {
            return JsonSerializer.Deserialize<BotDeviceInfo>(File.ReadAllText(DevicePath));
        }
        catch (Exception e)
        {
            _logger.LogWarning(e, "Failed to read existing device fields while initializing SignServer synthetic profile");
            return null;
        }
    }

    private static byte[]? TryParseMac(string mac)
    {
        try
        {
            var bytes = mac.Split(':').Select(part => Convert.ToByte(part, 16)).ToArray();
            return bytes.Length == 6 ? bytes : null;
        }
        catch
        {
            return null;
        }
    }

    private static string FormatMac(byte[] mac)
        => string.Join(':', mac.Take(6).Select(value => value.ToString("x2")));

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true
    };
}

public sealed class SignServerProfile
{
    private sealed record EnvironmentTemplate(
        string HostPrefix,
        string DeviceName,
        string HardwareModel,
        string OsRelease,
        string Timezone,
        string ProcCmdline,
        int Weight);

    private static readonly EnvironmentTemplate[] EnvironmentTemplates =
    {
        new("uos-office", "ThinkCentre M720q", "Lenovo ThinkCentre M720q", "Linux 5.10.0-amd64-desktop x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 18),
        new("deepin-desk", "OptiPlex 3070 Micro", "Dell OptiPlex 3070 Micro", "Linux 6.6.25-amd64-desktop-hwe x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 18),
        new("uos-prodesk", "ProDesk 400 G5 DM", "HP ProDesk 400 G5 Desktop Mini", "Linux 5.15.0-amd64-desktop x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=audio.mojom.AudioService", 16),
        new("uos-mini", "ThinkCentre M75q Gen 2", "Lenovo ThinkCentre M75q Gen 2", "Linux 5.10.0-amd64-desktop x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 16),
        new("deepin-pc", "OptiPlex 7090", "Dell OptiPlex 7090", "Linux 6.6.25-amd64-desktop-hwe x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=gpu-process", 14),
        new("steamdeck", "Steam Deck", "Valve Jupiter", "Linux 6.5.0-valve22-1-neptune-65 x86_64", "Asia/Shanghai",
            "/usr/bin/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 12),
        new("bazzite", "ROG Ally RC71L", "ASUSTeK ROG Ally RC71L", "Linux 6.8.10-bazzite x86_64", "Asia/Shanghai",
            "/usr/lib64/qq/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 10),
        new("legiongo", "Legion Go 8APU1", "Lenovo Legion Go 8APU1", "Linux 6.8.10-bazzite x86_64", "Asia/Shanghai",
            "/usr/lib64/qq/qq|--type=gpu-process", 9),
        new("nitro", "Nitro AN515-58", "Acer Nitro AN515-58", "Linux 6.8.10-bazzite x86_64", "Asia/Shanghai",
            "/usr/lib64/qq/qq|--type=utility|--lang=zh-CN", 8),
        new("legion", "Legion 5 15ACH6", "Lenovo Legion 5 15ACH6", "Linux 6.8.10-bazzite x86_64", "Asia/Shanghai",
            "/usr/lib64/qq/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 8),
        new("zephyrus", "ROG Zephyrus G14 GA401", "ASUSTeK ROG Zephyrus G14 GA401", "Linux 6.8.10-bazzite x86_64", "Asia/Shanghai",
            "/usr/lib64/qq/qq|--type=utility|--utility-sub-type=audio.mojom.AudioService", 7),
        new("framework", "Framework Laptop 13", "Framework Laptop 13", "Linux 6.8.9-300.fc40.x86_64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 8),
        new("system76", "System76 Lemur Pro", "System76 Lemur Pro", "Linux 6.8.0-31-generic x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 7),
        new("tuxedo", "TUXEDO Pulse 14", "TUXEDO Pulse 14", "Linux 6.8.0-31-generic x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=audio.mojom.AudioService", 7),
        new("slimbook", "Slimbook Executive 14", "Slimbook Executive 14", "Linux 6.8.9-300.fc40.x86_64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 6),
        new("aurora", "ThinkPad T14 Gen 3", "Lenovo ThinkPad T14 Gen 3", "Linux 6.8.0-60-generic x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 6),
        new("workstation", "ThinkPad X1 Carbon Gen 10", "Lenovo ThinkPad X1 Carbon Gen 10", "Linux 6.6.15-amd64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 4),
        new("xps", "XPS 13 9310", "Dell XPS 13 9310", "Linux 6.1.0-21-amd64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=gpu-process", 4),
        new("matebook", "MateBook 14 2021", "HUAWEI MateBook 14 2021", "Linux 6.9.7-arch1-1 x86_64", "Asia/Shanghai",
            "/usr/lib/qq/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 4),
        new("thinkpad", "ThinkPad T480", "Lenovo ThinkPad T480", "Linux 6.1.0-21-amd64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 4),
        new("latitude", "Latitude 5420", "Dell Latitude 5420", "Linux 6.8.0-31-generic x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=audio.mojom.AudioService", 4),
        new("officebook", "EliteBook 845 G8", "HP EliteBook 845 G8 Notebook PC", "Linux 6.5.0-35-generic x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 4),
        new("x260", "ThinkPad X260", "Lenovo ThinkPad X260", "Linux 6.1.0-21-amd64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 4),
        new("old-desk", "OptiPlex 7040", "Dell OptiPlex 7040", "Linux 6.1.0-21-amd64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=audio.mojom.AudioService", 4),
        new("h110", "Core i5-6500 Desktop", "Gigabyte H110M-S2PH", "Linux 6.6.15-amd64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 3),
        new("x99", "Xeon E5-2678 v3 Desktop", "ASUS X99-A II", "Linux 6.1.0-21-amd64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=gpu-process", 3),
        new("e5box", "Xeon E5-2680 v4 Desktop", "Gigabyte X99-UD4", "Linux 6.6.15-amd64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--lang=zh-CN", 3),
        new("b450", "Ryzen 5 3600 Desktop", "MSI B450M MORTAR MAX", "Linux 6.8.0-31-generic x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 3),
        new("b550", "Ryzen 7 3700X Desktop", "Gigabyte B550M AORUS ELITE", "Linux 6.8.9-300.fc40.x86_64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=audio.mojom.AudioService", 3),
        new("minipc", "SER5 MAX", "MINISFORUM SER5 MAX", "Linux 6.7.12-200.fc39.x86_64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 4),
        new("labpc", "B660M DS3H DDR4", "Gigabyte B660M DS3H DDR4 Desktop", "Linux 6.7.12-200.fc39.x86_64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=zygote", 3),
        new("zen5", "Ryzen 9 9950X Desktop", "ASUS ProArt X870E-CREATOR WIFI", "Linux 6.10.2-arch1-1 x86_64", "Asia/Shanghai",
            "/usr/lib/qq/qq|--type=utility|--lang=zh-CN", 3),
        new("raptor", "Core i9-14900K Desktop", "ASUS ROG MAXIMUS Z790 HERO", "Linux 6.9.12-200.fc40.x86_64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=zygote", 3),
        new("aorus", "Core i9-14900K Workstation", "Gigabyte Z790 AORUS MASTER X", "Linux 6.9.12-200.fc40.x86_64 x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 2),
        new("ultra9", "Core Ultra 9 285K Workstation", "MSI MPG Z890 CARBON WIFI", "Linux 6.11.4-arch1-1 x86_64", "Asia/Shanghai",
            "/usr/lib/qq/qq|--type=utility|--utility-sub-type=audio.mojom.AudioService", 2),
        new("threadripper", "Threadripper PRO 7975WX Workstation", "ASUS Pro WS WRX90E-SAGE SE", "Linux 6.10.2-arch1-1 x86_64", "Asia/Shanghai",
            "/usr/lib/qq/qq|--type=utility|--lang=zh-CN", 2),
        new("precision", "Precision 5860 Tower", "Dell Precision 5860 Tower", "Linux 6.8.0-31-generic x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 2),
        new("thinkstation", "ThinkStation P3 Tower", "Lenovo ThinkStation P3 Tower", "Linux 6.8.0-31-generic x86_64", "Asia/Shanghai",
            "/opt/QQ/qq|--type=utility|--utility-sub-type=network.mojom.NetworkService", 2)
    };

    [JsonPropertyName("schema_version")] public int SchemaVersion { get; set; } = 1;

    [JsonPropertyName("profile_id")] public string ProfileId { get; set; } = "";

    [JsonPropertyName("created_at_unix")] public long CreatedAtUnix { get; set; }

    [JsonPropertyName("wrapper_version")] public string WrapperVersion { get; set; } = "49738";

    [JsonPropertyName("protocol")] public string Protocol { get; set; } = "Linux";

    [JsonPropertyName("app")] public SignServerProfileApp App { get; set; } = new();

    [JsonPropertyName("identity")] public SignServerProfileIdentity Identity { get; set; } = new();

    [JsonPropertyName("environment")] public SignServerProfileEnvironment Environment { get; set; } = new();

    [JsonPropertyName("online_state")] public SignServerOnlineState OnlineState { get; set; } = new();

    [JsonPropertyName("secure_state")] public SignServerSecureState SecureState { get; set; } = new();

    [JsonPropertyName("oidb102a_state")] public SignServerOidb102AState Oidb102AState { get; set; } = new();

    [JsonPropertyName("sso_report_source")] public SignServerSsoReportSource SsoReportSource { get; set; } = new();

    [JsonPropertyName("runtime_manifest")] public SignServerRuntimeManifestCache? RuntimeManifest { get; set; }

    public static SignServerProfile Create(string wrapperVersion, BotDeviceInfo? existing = null)
    {
        var guidBytes = RandomNumberGenerator.GetBytes(16);
        var guid = existing?.Guid ?? new Guid(guidBytes);
        var machineId = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant();
        var mac = existing?.MacAddress is { Length: >= 6 } existingMac
            ? string.Join(':', existingMac.Take(6).Select(value => value.ToString("x2")))
            : $"02:{machineId[0..2]}:{machineId[2..4]}:{machineId[4..6]}:{machineId[6..8]}:{machineId[8..10]}";
        var sessionSuffix = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLowerInvariant();
        var template = SelectWeightedTemplate();
        var hostSuffix = RandomNumberGenerator.GetInt32(10, 99).ToString();
        var profileId = $"lagrange-{wrapperVersion}-profile-{sessionSuffix}";
        var qimei36 = GenerateQimei36(profileId, "0", guid);

        return new SignServerProfile
        {
            ProfileId = profileId,
            CreatedAtUnix = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            WrapperVersion = wrapperVersion,
            App = new SignServerProfileApp(),
            Identity = new SignServerProfileIdentity
            {
                Session = $"lagrange-{wrapperVersion}-profile-{sessionSuffix}",
                Guid = guid.ToString(),
                MachineId = machineId,
                MacAddress = mac,
                Qimei36 = qimei36,
                Qimei36Uin = "0"
            },
            Environment = SignServerProfileEnvironment.FromTemplate(
                template.HostPrefix,
                template.DeviceName,
                template.HardwareModel,
                template.OsRelease,
                template.Timezone,
                template.ProcCmdline,
                hostSuffix),
            SsoReportSource = SignServerSsoReportSource.FromTemplate(template.HardwareModel)
        };
    }

    internal static string GenerateQimei36(string profileSeed, string uin, Guid deviceGuid)
    {
        var input = $"qimei36-v1{profileSeed}{uin}{deviceGuid:N}";
        return Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(input)))
            .ToLowerInvariant()[..36];
    }

    private static EnvironmentTemplate SelectWeightedTemplate()
    {
        var totalWeight = EnvironmentTemplates.Sum(template => template.Weight);
        var selected = RandomNumberGenerator.GetInt32(totalWeight);

        foreach (var template in EnvironmentTemplates)
        {
            if (selected < template.Weight) return template;
            selected -= template.Weight;
        }

        return EnvironmentTemplates[^1];
    }
}

public sealed class SignServerProfileApp
{
    [JsonPropertyName("qua")] public string Qua { get; set; } = "V1_LNX_NQ_3.2.29_49738_GW_B";

    [JsonPropertyName("current_version")] public string CurrentVersion { get; set; } = "3.2.29-49738";

    [JsonPropertyName("platform")] public string Platform { get; set; } = "Linux";
}

public sealed class SignServerRuntimeManifestCache
{
    [JsonPropertyName("version")] public string Version { get; set; } = "";

    [JsonPropertyName("fetched_at_unix")] public long FetchedAtUnix { get; set; }

    [JsonPropertyName("length")] public int Length { get; set; }

    [JsonPropertyName("sha256_16")] public string Sha256_16 { get; set; } = "";
}

public sealed class SignServerSsoReportSource
{
    [JsonPropertyName("report_type")] public int ReportType { get; set; } = 1;

    [JsonPropertyName("brand")] public string Brand { get; set; } = "Lenovo";

    [JsonPropertyName("model")] public string Model { get; set; } = "ThinkPad T14 Gen 2";

    [JsonPropertyName("device_type")] public int DeviceType { get; set; } = 2;

    [JsonPropertyName("version")] public string Version { get; set; } = "3.2.29-49738";

    [JsonPropertyName("version_entries")] public List<SignServerVersionEntry> VersionEntries { get; set; } =
    [
        new SignServerVersionEntry()
    ];

    [JsonPropertyName("opaque_field4_hex")] public string OpaqueField4Hex { get; set; } = "";

    internal static SignServerSsoReportSource FromTemplate(string hardwareModel)
    {
        var (brand, model) = SplitBrandModel(hardwareModel);
        return new SignServerSsoReportSource
        {
            Brand = brand,
            Model = model,
            DeviceType = 2,
            Version = "3.2.29-49738",
            VersionEntries = [new SignServerVersionEntry()]
        };
    }

    private static (string Brand, string Model) SplitBrandModel(string hardwareModel)
    {
        var knownBrands = new[]
        {
            "Lenovo", "Dell", "HP", "ASUSTeK", "ASUS", "Acer", "Valve", "System76", "TUXEDO",
            "Slimbook", "HUAWEI", "Gigabyte", "MSI", "MINISFORUM", "Framework"
        };

        foreach (var brand in knownBrands)
        {
            if (!hardwareModel.StartsWith(brand, StringComparison.OrdinalIgnoreCase)) continue;
            var model = hardwareModel[brand.Length..].Trim();
            return (brand, string.IsNullOrEmpty(model) ? hardwareModel : model);
        }

        var parts = hardwareModel.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 2 ? (parts[0], parts[1]) : ("Generic", hardwareModel);
    }
}

public sealed class SignServerVersionEntry
{
    [JsonPropertyName("group")] public string Group { get; set; } = "LinuxQQ";

    [JsonPropertyName("old_version")] public string OldVersion { get; set; } = "3.2.29-49738";

    [JsonPropertyName("group_id")] public int GroupId { get; set; }

    [JsonPropertyName("new_version")] public int NewVersion { get; set; } = 49738;
}

public sealed class SignServerProfileIdentity
{
    [JsonPropertyName("uin")] public string Uin { get; set; } = "0";

    [JsonPropertyName("session")] public string Session { get; set; } = "";

    [JsonPropertyName("guid")] public string Guid { get; set; } = "";

    [JsonPropertyName("machine_id")] public string MachineId { get; set; } = "";

    [JsonPropertyName("mac_address")] public string MacAddress { get; set; } = "";

    [JsonPropertyName("qimei36")] public string Qimei36 { get; set; } = "";

    [JsonPropertyName("qimei36_uin")] public string Qimei36Uin { get; set; } = "";
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

    [JsonPropertyName("hostname")] public string Hostname { get; set; } = "thinkpad";

    [JsonPropertyName("device_name")] public string DeviceName { get; set; } = "ThinkPad T14 Gen 3";

    [JsonPropertyName("distro")] public string Distro { get; set; } = "Debian GNU/Linux 12";

    [JsonPropertyName("kernel")] public string Kernel { get; set; } = "6.1.0-23-amd64";

    [JsonPropertyName("desktop_env")] public string DesktopEnv { get; set; } = "GNOME";

    [JsonPropertyName("session_type")] public string SessionType { get; set; } = "x11";

    [JsonPropertyName("vendor")] public string Vendor { get; set; } = "Lenovo";

    [JsonPropertyName("model")] public string Model { get; set; } = "ThinkPad T14 Gen 3";

    [JsonPropertyName("env_id_str")] public string EnvIdStr { get; set; } = "";

    [JsonPropertyName("is_test_env")] public bool IsTestEnv { get; set; }

    [JsonPropertyName("canary")] public string Canary { get; set; } = "";

    [JsonPropertyName("locale_id")] public int LocaleId { get; set; } = 2052;

    [JsonPropertyName("vendor_name")] public string VendorName { get; set; } = "";

    [JsonPropertyName("os_lower")] public string OsLower { get; set; } = "linux";

    internal static SignServerProfileEnvironment FromTemplate(
        string hostPrefix,
        string deviceName,
        string hardwareModel,
        string osRelease,
        string timezone,
        string procCmdline,
        string hostSuffix) => new()
        {
            FakeHostname = $"{hostPrefix}-{hostSuffix}",
            FakeProcComm = "qq",
            FakeProcCmdline = procCmdline,
            FakeDeviceName = deviceName,
            FakeHardwareModel = hardwareModel,
            FakeOsRelease = osRelease,
            FakeTimezone = timezone,
            Hostname = $"{hostPrefix}-{hostSuffix}",
            DeviceName = deviceName,
            Distro = GuessDistro(osRelease),
            Kernel = osRelease.Replace("Linux ", "").Replace(" x86_64", ""),
            DesktopEnv = GuessDesktop(osRelease),
            SessionType = "x11",
            Vendor = SplitVendorModel(hardwareModel).Vendor,
            Model = SplitVendorModel(hardwareModel).Model,
            LocaleId = 2052,
            VendorName = "",
            OsLower = "linux"
        };

    private static string GuessDistro(string osRelease)
    {
        if (osRelease.Contains("bazzite", StringComparison.OrdinalIgnoreCase)) return "Bazzite";
        if (osRelease.Contains("arch", StringComparison.OrdinalIgnoreCase)) return "Arch Linux";
        if (osRelease.Contains("fc", StringComparison.OrdinalIgnoreCase)) return "Fedora Linux";
        if (osRelease.Contains("generic", StringComparison.OrdinalIgnoreCase)) return "Ubuntu 24.04 LTS";
        if (osRelease.Contains("desktop", StringComparison.OrdinalIgnoreCase)) return "UOS Desktop";
        return "Debian GNU/Linux 12";
    }

    private static string GuessDesktop(string osRelease)
    {
        if (osRelease.Contains("bazzite", StringComparison.OrdinalIgnoreCase)) return "KDE";
        if (osRelease.Contains("desktop", StringComparison.OrdinalIgnoreCase)) return "DDE";
        return "GNOME";
    }

    private static (string Vendor, string Model) SplitVendorModel(string hardwareModel)
    {
        var parts = hardwareModel.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length == 2 ? (parts[0], parts[1]) : ("Generic", hardwareModel);
    }
}

public sealed class SignServerOnlineState
{
    [JsonPropertyName("online_push_flags")] public uint OnlinePushFlags { get; set; }

    [JsonPropertyName("heartbeat_counter")] public uint HeartbeatCounter { get; set; }

    [JsonPropertyName("last_push_command")] public string? LastPushCommand { get; set; }

    [JsonPropertyName("last_push_branch")] public string? LastPushBranch { get; set; }

    [JsonPropertyName("last_push_field1")] public string? LastPushField1 { get; set; }

    [JsonPropertyName("push_params_count")] public uint PushParamsCount { get; set; }

    [JsonPropertyName("push_params_last_field1")] public string? PushParamsLastField1 { get; set; }

    [JsonPropertyName("push_params_last_hash")] public string? PushParamsLastHash { get; set; }

    [JsonPropertyName("info_sync_push_count")] public uint InfoSyncPushCount { get; set; }

    [JsonPropertyName("info_sync_push_variant_counts")] public Dictionary<string, uint> InfoSyncPushVariantCounts { get; set; } = new();

    [JsonPropertyName("info_sync_push_last_field3")] public string? InfoSyncPushLastField3 { get; set; }

    [JsonPropertyName("info_sync_push_last_field4")] public string? InfoSyncPushLastField4 { get; set; }

    [JsonPropertyName("info_sync_push_last_hash")] public string? InfoSyncPushLastHash { get; set; }

    [JsonPropertyName("config_push_count")] public uint ConfigPushCount { get; set; }

    [JsonPropertyName("config_push_last_hash")] public string? ConfigPushLastHash { get; set; }

    [JsonPropertyName("msf_login_notify_count")] public uint MsfLoginNotifyCount { get; set; }

    [JsonPropertyName("msf_login_notify_last_hash")] public string? MsfLoginNotifyLastHash { get; set; }

    [JsonPropertyName("last_sso_info_sync_seq")] public uint LastSsoInfoSyncSeq { get; set; }

    [JsonPropertyName("last_heartbeat_seq")] public uint LastHeartbeatSeq { get; set; }

    [JsonPropertyName("last_native_tiers")] public Dictionary<string, string> LastNativeTiers { get; set; } = new();

    [JsonPropertyName("transinfo")] public Dictionary<string, SignServerStateHash> TransInfo { get; set; } = new();

    [JsonPropertyName("transinfo_values")] public Dictionary<string, string> TransInfoValues { get; set; } = new();

    [JsonPropertyName("register_context")] public SignServerStateHash RegisterContext { get; set; } = new();

    [JsonPropertyName("register_context_hex")] public string RegisterContextHex { get; set; } = "";
}

public sealed class SignServerSecureState
{
    [JsonPropertyName("last_command")] public string? LastCommand { get; set; }

    [JsonPropertyName("last_seq")] public uint LastSeq { get; set; }

    [JsonPropertyName("last_payload")] public SignServerStateHash LastPayload { get; set; } = new();

    [JsonPropertyName("last_reserve")] public SignServerStateHash LastReserve { get; set; } = new();

    [JsonPropertyName("establish_count")] public uint EstablishCount { get; set; }

    [JsonPropertyName("secure_access_count")] public uint SecureAccessCount { get; set; }
}

public sealed class SignServerOidb102AState
{
    [JsonPropertyName("last_command")] public string? LastCommand { get; set; }

    [JsonPropertyName("last_seq")] public uint LastSeq { get; set; }

    [JsonPropertyName("last_response")] public SignServerStateHash LastResponse { get; set; } = new();

    [JsonPropertyName("client_key_response_count")] public uint ClientKeyResponseCount { get; set; }

    [JsonPropertyName("cookie_response_count")] public uint CookieResponseCount { get; set; }
}

public sealed class SignServerStateHash
{
    [JsonPropertyName("len")] public int Len { get; set; }

    [JsonPropertyName("sha256_16")] public string Sha256_16 { get; set; } = "";
}
