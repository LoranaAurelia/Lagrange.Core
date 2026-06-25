namespace Lagrange.Core.Utility.Sign;

public abstract class SignProvider
{
    protected bool Available = true;

    public virtual bool UseNativeBodyForOnline => false;

    public virtual bool StrictNativeTier => false;

    public virtual bool ShouldUseNativeBody(string command, SignResult result) => false;

    protected static readonly string[] WhiteListCommand =
    {
        "trpc.o3.ecdh_access.EcdhAccess.SsoEstablishShareKey",
        "trpc.o3.ecdh_access.EcdhAccess.SsoSecureAccess",
        "trpc.o3.report.Report.SsoReport",
        "MessageSvc.PbSendMsg",
        "wtlogin.trans_emp",
        "wtlogin.login",
        "trpc.login.ecdh.EcdhService.SsoKeyExchange",
        "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLogin",
        "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLogin",
        "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginNewDevice",
        "trpc.login.ecdh.EcdhService.SsoNTLoginEasyLoginUnusualDevice",
        "trpc.login.ecdh.EcdhService.SsoNTLoginPasswordLoginUnusualDevice",
        "OidbSvcTrpcTcp.0x11ec_1",
        "OidbSvcTrpcTcp.0x758_1", // create group
        "OidbSvcTrpcTcp.0x7c1_1",
        "OidbSvcTrpcTcp.0x7c2_5", // request friend
        "OidbSvcTrpcTcp.0x10db_1",
        "OidbSvcTrpcTcp.0x8a1_7", // request group
        "OidbSvcTrpcTcp.0x89a_0",
        "OidbSvcTrpcTcp.0x89a_15",
        "OidbSvcTrpcTcp.0x88d_0", // fetch group detail
        "OidbSvcTrpcTcp.0x88d_14",
        "OidbSvcTrpcTcp.0x112a_1",
        "OidbSvcTrpcTcp.0x587_74",
        "OidbSvcTrpcTcp.0x1100_1",
        "OidbSvcTrpcTcp.0x1102_1",
        "OidbSvcTrpcTcp.0x1103_1",
        "OidbSvcTrpcTcp.0x1107_1",
        "OidbSvcTrpcTcp.0x1105_1",
        "OidbSvcTrpcTcp.0xf88_1",
        "OidbSvcTrpcTcp.0xf89_1",
        "OidbSvcTrpcTcp.0xf57_1",
        "OidbSvcTrpcTcp.0xf57_106",
        "OidbSvcTrpcTcp.0xf57_9",
        "OidbSvcTrpcTcp.0xf55_1",
        "OidbSvcTrpcTcp.0xf67_1",
        "OidbSvcTrpcTcp.0xf67_5",
        "OidbSvcTrpcTcp.0x6d9_4",
        "trpc.msg.register_proxy.RegisterProxy.SsoInfoSync",
        "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat",
        "trpc.qq_new_tech.status_svc.StatusService.Register"
    };

    public abstract byte[]? Sign(string cmd, uint seq, byte[] body, out byte[]? ver, out string? token);

    public virtual SignResult SignPacket(SignRequestContext context)
    {
        var sign = Sign(context.Command, context.Sequence, context.Body, out var extra, out var token);
        return new SignResult
        {
            Sign = sign,
            Extra = extra,
            Token = token
        };
    }

    public virtual void PushState(SignStatePushContext context) { }

    public static bool IsRoutedOnlineCommand(string command) => command is
        "trpc.msg.register_proxy.RegisterProxy.SsoInfoSync" or
        "trpc.qq_new_tech.status_svc.StatusService.SsoHeartBeat" or
        "trpc.qq_new_tech.status_svc.StatusService.Register";

    public static bool IsRoutedReportCommand(string command) =>
        command == "trpc.o3.report.Report.SsoReport";
}

public sealed class SignRequestContext
{
    public string Command { get; init; } = "";

    public uint Sequence { get; init; }

    public byte[] Body { get; init; } = Array.Empty<byte>();

    public Lagrange.Core.Common.BotAppInfo AppInfo { get; init; } = null!;

    public Lagrange.Core.Common.BotDeviceInfo DeviceInfo { get; init; } = null!;

    public Lagrange.Core.Common.BotKeystore Keystore { get; init; } = null!;
}

public sealed class SignResult
{
    public byte[]? Sign { get; init; }

    public byte[]? Extra { get; init; }

    public string? Token { get; init; }

    public int? TokenLength { get; init; }

    public byte[]? NativeBody { get; init; }

    public string? NativeTier { get; init; }

    public IReadOnlyList<SignStateUpdate> StateUpdates { get; init; } = Array.Empty<SignStateUpdate>();

    public string? Diagnostic { get; init; }

    public string? ExtraFields { get; init; }
}

public sealed class SignStateUpdate
{
    public string? Kind { get; init; }

    public int? Len { get; init; }

    public string? Sha256_16 { get; init; }
}

public sealed class SignStatePushContext
{
    public string Command { get; init; } = "";

    public uint Sequence { get; init; }

    public byte[] Payload { get; init; } = Array.Empty<byte>();

    public byte[] ReserveField { get; init; } = Array.Empty<byte>();

    public object? ReserveFields { get; init; }

    public Lagrange.Core.Common.BotKeystore Keystore { get; init; } = null!;
}
