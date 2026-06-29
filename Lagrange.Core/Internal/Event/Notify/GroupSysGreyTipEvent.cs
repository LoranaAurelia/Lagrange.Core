namespace Lagrange.Core.Internal.Event.Notify;

internal class GroupSysGreyTipEvent : ProtocolEvent
{
    public uint GroupUin { get; }

    public uint SubType { get; }

    public uint Type { get; }

    public ulong BusiType { get; }

    public ulong TemplId { get; }

    public ulong MessageSequence { get; }

    public ulong TipsSeqId { get; }

    public string Text { get; }

    public string Url { get; }

    public IReadOnlyDictionary<string, string> Parameters { get; }

    public byte[] RawPayload { get; }

    public string Detection { get; }

    public string? Error { get; }

    private GroupSysGreyTipEvent(uint groupUin, uint subType, uint type, ulong busiType, ulong templId,
        ulong messageSequence, ulong tipsSeqId, string text, string url, IReadOnlyDictionary<string, string> parameters,
        byte[] rawPayload, string detection, string? error)
        : base(0)
    {
        GroupUin = groupUin;
        SubType = subType;
        Type = type;
        BusiType = busiType;
        TemplId = templId;
        MessageSequence = messageSequence;
        TipsSeqId = tipsSeqId;
        Text = text;
        Url = url;
        Parameters = parameters;
        RawPayload = rawPayload;
        Detection = detection;
        Error = error;
    }

    public static GroupSysGreyTipEvent Result(uint groupUin, uint subType, uint type, ulong busiType, ulong templId,
        ulong messageSequence, ulong tipsSeqId, string text, string url, IReadOnlyDictionary<string, string> parameters,
        byte[]? rawPayload = null, string detection = "", string? error = null)
        => new(groupUin, subType, type, busiType, templId, messageSequence, tipsSeqId, text, url, parameters,
            rawPayload ?? Array.Empty<byte>(), detection, error);
}
