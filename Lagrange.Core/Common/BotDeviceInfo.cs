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

    public static BotDeviceInfo GenerateInfo() => new()
    {
        Guid = Guid.NewGuid(),
        MacAddress = ByteGen.GenRandomBytes(6),
        DeviceName = "ThinkPad T14 Gen 3",
        SystemKernel = "Linux 6.8.0-60-generic",
        KernelVersion = "6.8.0-60-generic"
    };
}
