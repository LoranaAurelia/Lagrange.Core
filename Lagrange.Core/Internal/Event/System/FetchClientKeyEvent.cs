namespace Lagrange.Core.Internal.Event.System;

internal class FetchClientKeyEvent : ProtocolEvent
{
    public string ClientKey { get; }

    public uint Expiration { get; }

    private FetchClientKeyEvent() : base(true)
    {
        ClientKey = "";
    }

    private FetchClientKeyEvent(int resultCode, string clientKey, uint expiration) : base(resultCode)
    {
        ClientKey = clientKey;
        Expiration = expiration;
    }

    public static FetchClientKeyEvent Create() => new();

    public static FetchClientKeyEvent Result(int resultCode, string clientKey, uint expiration) => new(resultCode, clientKey, expiration);
}
