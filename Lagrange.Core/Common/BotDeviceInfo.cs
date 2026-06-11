using System.Security.Cryptography;
using Lagrange.Core.Utility.Generator;

#pragma warning disable CS8618

namespace Lagrange.Core.Common;

[Serializable]
public class BotDeviceInfo
{
    public Guid Guid { get; set; }
    
    public byte[] MacAddress { get; set; }
    
    public string DeviceName { get; set; }
    
    public string SystemKernel { get; set; }
    
    public string KernelVersion { get; set; }

    private static readonly (string Name, string Kernel, string Version, int Weight)[] LinuxProfiles = new[]
    {
        ("ThinkCentre M720q", "Linux 5.10.0-amd64-desktop", "5.10.0-amd64-desktop", 18),
        ("OptiPlex 3070 Micro", "Linux 6.6.25-amd64-desktop-hwe", "6.6.25-amd64-desktop-hwe", 18),
        ("ProDesk 400 G5 DM", "Linux 5.15.0-amd64-desktop", "5.15.0-amd64-desktop", 16),
        ("ThinkCentre M75q Gen 2", "Linux 5.10.0-amd64-desktop", "5.10.0-amd64-desktop", 16),
        ("OptiPlex 7090", "Linux 6.6.25-amd64-desktop-hwe", "6.6.25-amd64-desktop-hwe", 14),
        ("Steam Deck", "Linux 6.5.0-valve22-1-neptune-65", "6.5.0-valve22-1-neptune-65", 12),
        ("ROG Ally RC71L", "Linux 6.8.10-bazzite", "6.8.10-bazzite", 10),
        ("Legion Go 8APU1", "Linux 6.8.10-bazzite", "6.8.10-bazzite", 9),
        ("Nitro AN515-58", "Linux 6.8.10-bazzite", "6.8.10-bazzite", 8),
        ("Legion 5 15ACH6", "Linux 6.8.10-bazzite", "6.8.10-bazzite", 8),
        ("ROG Zephyrus G14 GA401", "Linux 6.8.10-bazzite", "6.8.10-bazzite", 7),
        ("Framework Laptop 13", "Linux 6.8.9-300.fc40.x86_64", "6.8.9-300.fc40.x86_64", 8),
        ("System76 Lemur Pro", "Linux 6.8.0-31-generic", "6.8.0-31-generic", 7),
        ("TUXEDO Pulse 14", "Linux 6.8.0-31-generic", "6.8.0-31-generic", 7),
        ("Slimbook Executive 14", "Linux 6.8.9-300.fc40.x86_64", "6.8.9-300.fc40.x86_64", 6),
        ("ThinkPad T14 Gen 3", "Linux 6.8.0-60-generic", "6.8.0-60-generic", 6),
        ("ThinkPad X1 Carbon Gen 10", "Linux 6.6.15-amd64", "6.6.15-amd64", 4),
        ("XPS 13 9310", "Linux 6.1.0-21-amd64", "6.1.0-21-amd64", 4),
        ("MateBook 14 2021", "Linux 6.9.7-arch1-1", "6.9.7-arch1-1", 4),
        ("ThinkPad T480", "Linux 6.1.0-21-amd64", "6.1.0-21-amd64", 4),
        ("Latitude 5420", "Linux 6.8.0-31-generic", "6.8.0-31-generic", 4),
        ("EliteBook 845 G8", "Linux 6.5.0-35-generic", "6.5.0-35-generic", 4),
        ("ThinkPad X260", "Linux 6.1.0-21-amd64", "6.1.0-21-amd64", 4),
        ("OptiPlex 7040", "Linux 6.1.0-21-amd64", "6.1.0-21-amd64", 4),
        ("H110M-S2PH", "Linux 6.6.15-amd64", "6.6.15-amd64", 3),
        ("X99-A II", "Linux 6.1.0-21-amd64", "6.1.0-21-amd64", 3),
        ("X99-UD4", "Linux 6.6.15-amd64", "6.6.15-amd64", 3),
        ("B450M MORTAR MAX", "Linux 6.8.0-31-generic", "6.8.0-31-generic", 3),
        ("B550M AORUS ELITE", "Linux 6.8.9-300.fc40.x86_64", "6.8.9-300.fc40.x86_64", 3),
        ("SER5 MAX", "Linux 6.7.12-200.fc39.x86_64", "6.7.12-200.fc39.x86_64", 4),
        ("B660M DS3H DDR4", "Linux 6.7.12-200.fc39.x86_64", "6.7.12-200.fc39.x86_64", 3),
        ("ProArt X870E-CREATOR WIFI", "Linux 6.10.2-arch1-1", "6.10.2-arch1-1", 3),
        ("ROG MAXIMUS Z790 HERO", "Linux 6.9.12-200.fc40.x86_64", "6.9.12-200.fc40.x86_64", 3),
        ("Z790 AORUS MASTER X", "Linux 6.9.12-200.fc40.x86_64", "6.9.12-200.fc40.x86_64", 2),
        ("MPG Z890 CARBON WIFI", "Linux 6.11.4-arch1-1", "6.11.4-arch1-1", 2),
        ("Pro WS WRX90E-SAGE SE", "Linux 6.10.2-arch1-1", "6.10.2-arch1-1", 2),
        ("Precision 5860 Tower", "Linux 6.8.0-31-generic", "6.8.0-31-generic", 2),
        ("ThinkStation P3 Tower", "Linux 6.8.0-31-generic", "6.8.0-31-generic", 2)
    };

    public static BotDeviceInfo GenerateInfo()
    {
        var profile = SelectWeightedProfile();
        return new BotDeviceInfo
        {
            Guid = Guid.NewGuid(),
            MacAddress = ByteGen.GenRandomBytes(6),
            DeviceName = profile.Name,
            SystemKernel = profile.Kernel,
            KernelVersion = profile.Version
        };
    }

    private static (string Name, string Kernel, string Version, int Weight) SelectWeightedProfile()
    {
        var totalWeight = LinuxProfiles.Sum(profile => profile.Weight);
        var selected = RandomNumberGenerator.GetInt32(totalWeight);

        foreach (var profile in LinuxProfiles)
        {
            if (selected < profile.Weight) return profile;
            selected -= profile.Weight;
        }

        return LinuxProfiles[^1];
    }
}
