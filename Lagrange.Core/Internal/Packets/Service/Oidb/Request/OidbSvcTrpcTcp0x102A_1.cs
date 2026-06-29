using ProtoBuf;

namespace Lagrange.Core.Internal.Packets.Service.Oidb.Request;

// ReSharper disable InconsistentNaming

/// <summary>
/// Fetch Client Key. Current captures show the wrapped OIDB request is not empty;
/// Lagrange builds the request locally and the SignServer route signs/echoes that body.
/// </summary>
[ProtoContract]
[OidbSvcTrpcTcp(0x102A, 1)]
internal class OidbSvcTrpcTcp0x102A_1
{
    
}