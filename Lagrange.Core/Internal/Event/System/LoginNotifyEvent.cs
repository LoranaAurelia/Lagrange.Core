namespace Lagrange.Core.Internal.Event.System;

internal class LoginNotifyEvent : ProtocolEvent
{
    public bool IsLogin { get; }

    public bool StateKnown { get; }
    
    public uint AppId { get; }
    
    public string Tag { get; }
    
    public string Message { get; }

    private LoginNotifyEvent(bool isLogin, bool stateKnown, uint appId, string tag, string message) : base(0)
    {
        IsLogin = isLogin;
        StateKnown = stateKnown;
        AppId = appId;
        Tag = tag;
        Message = message;
    }

    public static LoginNotifyEvent Result(bool isLogin, bool stateKnown, uint appId, string tag, string message) =>
        new(isLogin, stateKnown, appId, tag, message);
}
