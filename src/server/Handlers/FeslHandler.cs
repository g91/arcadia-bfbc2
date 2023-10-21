using System.Globalization;
using Arcadia.EA;
using Arcadia.EA.Constants;
using Arcadia.PSN;
using Arcadia.Storage;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Org.BouncyCastle.Tls;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Arcadia.Handlers;

public class FeslHandler
{
    private readonly ILogger<FeslHandler> _logger;
    private readonly IOptions<ArcadiaSettings> _settings;
    private readonly SharedCounters _sharedCounters;
    private readonly SharedCache _sharedCache;

    public FeslHandler(ILogger<FeslHandler> logger, IOptions<ArcadiaSettings> settings, SharedCounters sharedCounters, SharedCache sharedCache)
    {
        _logger = logger;
        _settings = settings;
        _sharedCounters = sharedCounters;
        _sharedCache = sharedCache;
    }

    private readonly Dictionary<string, object> _sessionCache = new();
    private TlsServerProtocol _network = null!;
    private string _clientEndpoint = null!;

    private uint _feslTicketId;

    public async Task HandleClientConnection(TlsServerProtocol network, string clientEndpoint)
    {
        _network = network;
        _clientEndpoint = clientEndpoint;

        while (_network.IsConnected)
        {
            int read;
            byte[]? readBuffer;

            try
            {
                (read, readBuffer) = await Utils.ReadApplicationDataAsync(_network);
            }
            catch
            {
                _logger.LogInformation("Connection has been closed with {endpoint}", _clientEndpoint);
                break;
            }

            if (read == 0)
            {
                continue;
            }

            var reqPacket = new Packet(readBuffer[..read]);

            reqPacket.DataDict.TryGetValue("TXN", out var txn);
            var reqTxn = txn as string ?? string.Empty;

            if (reqTxn != "MemCheck")
            {
                _logger.LogDebug("Type: {type} | TXN: {txn}", reqPacket.Type, reqTxn);
            }

            if (reqPacket.Type == "fsys" && reqTxn == "Hello")
            {
                await HandleHello(reqPacket);
            }
            else if(reqPacket.Type == "pnow" && reqTxn == "Start")
            {
                await HandlePlayNow(reqPacket);
            }
            else if (reqPacket.Type == "fsys" && reqTxn == "MemCheck")
            {
                await HandleMemCheck();
            }
            else if (reqPacket.Type == "fsys" && reqTxn == "GetPingSites")
            {
                await HandleGetPingSites(reqPacket);
            }
            else if(reqPacket.Type == "acct" && reqTxn == "NuPS3Login")
            {
                await HandleLogin(reqPacket);
            }
            else if(reqPacket.Type == "acct" && reqTxn == "NuGetTos")
            {
                await HandleGetTos(reqPacket);
            }
            else if(reqPacket.Type == "acct" && reqTxn == "GetTelemetryToken")
            {
                await HandleTelemetryToken(reqPacket);
            }
            else if(reqPacket.Type == "acct" && reqTxn == "NuPS3AddAccount")
            {
                await HandleAddAccount(reqPacket);
            }
            else if(reqPacket.Type == "acct" && reqTxn == "NuLookupUserInfo")
            {
                await HandleLookupUserInfo(reqPacket);
            }
            else if(reqPacket.Type == "asso" && reqTxn == "GetAssociations")
            {
                await HandleGetAssociations(reqPacket);
            }
            else if(reqPacket.Type == "pres" && reqTxn == "PresenceSubscribe")
            {
                await HandlePresenceSubscribe(reqPacket);
            }
            else if(reqPacket.Type == "pres" && reqTxn == "SetPresenceStatus")
            {
                await HandleSetPresenceStatus(reqPacket);
            }
            else if (reqPacket.Type == "rank" && reqTxn == "GetStats")
            {
                await HandleGetStats(reqPacket);
            }
            else if (reqPacket.Type == "acct" && reqTxn == "NuLogin")
            {
                await HandleLogin3(reqPacket);
            }
            else if (reqPacket.Type == "acct" && reqTxn == "Login")
            {
                await HandleLogin2(reqPacket);
            }
            else if (reqPacket.Type == "acct" && reqTxn == "NuGetPersonas")
            {
                await HandleNuGetPersonas(reqPacket);
            }
            else if (reqPacket.Type == "acct" && reqTxn == "NuLoginPersona")
            {
                await HandleNuLoginPersona(reqPacket);
            }
            else if (reqPacket.Type == "acct" && reqTxn == "NuGetEntitlements")
            {
                await HandleNuGetEntitlements(reqPacket);
            }
            else if (reqPacket.Type == "acct" && reqTxn == "GetAccount")
            {
                await HandleGetAccount(reqPacket);
            }
            else if (reqPacket.Type == "acct" && reqTxn == "GameSpyPreAuth")
            {
                await HandleGameSpyPreAuth(reqPacket);
            }
            else if (reqPacket.Type == "acct" && reqTxn == "GetSubAccounts")
            {
                await HandleGetSubAccounts(reqPacket);
            }
            else if (reqPacket.Type == "acct" && reqTxn == "LoginSubAccount")
            {
                await HandleLoginSubAccount(reqPacket);
            }


            else if (reqPacket.Type == "acct" && reqTxn == "GetLockerURL")
            {
                await HandleGetLockerURL(reqPacket);
            }
            else if (reqPacket.Type == "xmsg" && reqTxn == "ModifySettings")
            {
                await HandleModifySettings(reqPacket);
            }
            else if (reqPacket.Type == "xmsg" && reqTxn == "GetMessages")
            {
                await HandleGetMessages(reqPacket);
            }
            else if (reqPacket.Type == "recp" && reqTxn == "GetRecordAsMap")
            {
                await HandleGetRecordAsMap(reqPacket);
            }
            else if (reqPacket.Type == "recp" && reqTxn == "GetRecord")
            {
                await HandleGetRecord(reqPacket);
            }
            else
            {
                _logger.LogWarning("Unknown packet type: {type}, TXN: {txn}", reqPacket.Type, reqTxn);
                Interlocked.Increment(ref _feslTicketId);
            }
        }
    }

    private async Task HandleTelemetryToken(Packet request)
    {
        var responseData = new Dictionary<string, object>
        {
            { "TXN", "GetTelemetryToken" },
        };

        var packet = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, responseData);
        var response = await packet.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    private async Task HandlePlayNow(Packet request)
    {
        var pnowId = _sharedCounters.GetNextPnowId();
        var gid = _sharedCounters.GetNextGameId();
        var lid = _sharedCounters.GetNextLobbyId();

        var data1 = new Dictionary<string, object>
        {
            { "TXN", "Start" },
            { "id.id", pnowId },
            { "id.partition", "/ps3/BEACH" },
        };

        var packet1 = new Packet("pnow", FeslTransmissionType.SinglePacketResponse, request.Id, data1);
        var response1 = await packet1.Serialize();
        _network.WriteApplicationData(response1.AsSpan());

        var data2 = new Dictionary<string, object>
        {
            { "TXN", "Status" },
            { "id.id", pnowId },
            { "id.partition", "/ps3/BEACH" },
            { "sessionState", "COMPLETE" },
            { "props.{}", 3 },
            { "props.{resultType}", "JOIN" },
            { "props.{avgFit}", "0.8182313914386985" },
            { "props.{games}.[]", 1 },
            { "props.{games}.0.gid", gid },
            { "props.{games}.0.lid", lid }
        };

        var packet2 = new Packet("pnow", FeslTransmissionType.SinglePacketResponse, request.Id, data2);
        var response2 = await packet2.Serialize();
        _network.WriteApplicationData(response2.AsSpan());

    }

    private async Task HandleGetStats(Packet request)
    {
        // TODO Not entirely sure if this works well with the game, since stats requests are usually sent as multi-packet queries with base64 encoded data
        var responseData = new Dictionary<string, object>
        {
            { "TXN", "GetStats" },
            {"stats.[]", 0 }
        };

        // TODO: Add some stats
        // var keysStr = request.DataDict["keys.[]"] as string ?? string.Empty;
        // var reqKeys = int.Parse(keysStr, CultureInfo.InvariantCulture);
        // for (var i = 0; i < reqKeys; i++)
        // {
        //     var key = request.DataDict[$"keys.{i}"];

        //     responseData.Add($"stats.{i}.key", key);
        //     responseData.Add($"stats.{i}.value", 0.0);
        // }

        var packet = new Packet("rank", FeslTransmissionType.SinglePacketResponse, request.Id, responseData);
        var response = await packet.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    private async Task HandlePresenceSubscribe(Packet request)
    {
        var responseData = new Dictionary<string, object>
        {
            { "TXN", "PresenceSubscribe" },
            { "responses.0.outcome", "0" },
            { "responses.[]", "1" },
            { "responses.0.owner.type", "1" },
            { "responses.0.owner.id", _sessionCache["UID"] },
        };

        var packet = new Packet("pres", FeslTransmissionType.SinglePacketResponse, request.Id, responseData);
        var response = await packet.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    private async Task HandleSetPresenceStatus(Packet request)
    {
        var responseData = new Dictionary<string, object>
        {
            { "TXN", "SetPresenceStatus" },
        };

        var packet = new Packet("pres", FeslTransmissionType.SinglePacketResponse, request.Id, responseData);
        var response = await packet.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    private async Task HandleLookupUserInfo(Packet request)
    {
        var responseData = new Dictionary<string, object>
        {
            { "TXN", "NuLookupUserInfo" },
            { "userInfo.[]", "1" },
            { "userInfo.0.userName", _sessionCache["personaName"] },
        };

        var packet = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, responseData);
        var response = await packet.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    private async Task HandleGetAssociations(Packet request)
    {
        var assoType = request.DataDict["type"] as string ?? string.Empty;
        var responseData = new Dictionary<string, object>
        {
            { "TXN", "GetAssociations" },
            { "domainPartition.domain", request.DataDict["domainPartition.domain"] },
            { "domainPartition.subDomain", request.DataDict["domainPartition.subDomain"] },
            { "owner.id", _sessionCache["UID"] },
            { "owner.type", "1" },
            { "type", assoType },
            { "members.[]", "0" },
        };

        if (assoType == "PlasmaMute")
        {
            responseData.Add("maxListSize", 100);
            responseData.Add("owner.name", _sessionCache["personaName"]);
        }
        else
        {
            _logger.LogWarning("Unknown association type: {assoType}", assoType);
        }

        var packet = new Packet("asso", FeslTransmissionType.SinglePacketResponse, request.Id, responseData);
        var response = await packet.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    private async Task HandleGetPingSites(Packet request)
    {
        const string serverIp = "127.0.0.1";

        var responseData = new Dictionary<string, object>
        {
            { "TXN", "GetPingSites" },
            { "pingSite.[]", "4"},
            { "pingSite.0.addr", serverIp },
            { "pingSite.0.type", "0"},
            { "pingSite.0.name", "eu1"},
            { "minPingSitesToPing", "0"}
        };

        var packet = new Packet("fsys", FeslTransmissionType.SinglePacketResponse, request.Id, responseData);
        var response = await packet.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    private async Task HandleHello(Packet request)
    {
        var currentTime = DateTime.UtcNow.ToString("MMM-dd-yyyy HH:mm:ss 'UTC'", CultureInfo.InvariantCulture);
        var serverHelloData = new Dictionary<string, object>
                {
                    { "domainPartition.domain", "ps3" },
                    { "messengerIp", "127.0.0.1" },
                    { "messengerPort", 0 },
                    { "domainPartition.subDomain", "BEACH" },
                    { "TXN", "Hello" },
                    { "activityTimeoutSecs", 0 },
                    { "curTime", currentTime},
                    { "theaterIp", _settings.Value.TheaterAddress },
                    { "theaterPort", _settings.Value.TheaterPort }
                };

        var helloPacket = new Packet("fsys", FeslTransmissionType.SinglePacketResponse, request.Id, serverHelloData);
        var helloResponse = await helloPacket.Serialize();

        _network.WriteApplicationData(helloResponse.AsSpan());

        await SendMemCheck();
    }

    private async Task HandleGetTos(Packet request)
    {
        // TODO Same as with stats, usually sent as multi-packed response
        const string tos = "Welcome to Arcadia!\nBeware, here be dragons!";

        var data = new Dictionary<string, object>
        {
            { "TXN", "NuGetTos" },
            { "version", "20426_17.20426_17" },
            { "tos", $"{System.Net.WebUtility.UrlEncode(tos).Replace('+', ' ')}" },
        };

        var packet = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await packet.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    private async Task HandleLogin(Packet request)
    {
        var encryptedSet = request.DataDict.TryGetValue("returnEncryptedInfo", out var returnEncryptedInfo);
        _logger.LogTrace("returnEncryptedInfo: {returnEncryptedInfo} ({encryptedSet})", returnEncryptedInfo, encryptedSet);

        // var tosAccepted = request.DataDict.TryGetValue("tosVersion", out var tosAcceptedValue);
        // if (false)
        // {
        //     loginResponseData.Add("TXN", request.Type);
        //     loginResponseData.Add("localizedMessage", "The password the user specified is incorrect");
        //     loginResponseData.Add("errorContainer.[]", "0");
        //     loginResponseData.Add("errorCode", "122");
        // }

        // if (!tosAccepted || string.IsNullOrEmpty(tosAcceptedValue as string))
        // {
        //     loginResponseData.Add("TXN", request.Type);
        //     loginResponseData.Add( "localizedMessage", "The user was not found" );
        //     loginResponseData.Add( "errorContainer.[]", 0 );
        //     loginResponseData.Add( "errorCode", 101 );
        // }
        // else
        // {
        //     const string keyTempl = "W5NyZzx{0}Cki6GQAAKDw.";
        //     var lkey = string.Format(keyTempl, "SaUr4131g");

        //     loginResponseData.Add("lkey", lkey);
        //     loginResponseData.Add("TXN", "NuPS3Login");
        //     loginResponseData.Add("userId", 1000000000000);
        //     loginResponseData.Add("personaName", "arcadia_ps3");
        // }

        var loginTicket = request.DataDict["ticket"] as string ?? string.Empty;
        var ticketData = TicketDecoder.DecodeFromASCIIString(loginTicket);
        var onlineId = (ticketData[5] as BStringData).Value.TrimEnd('\0');

        _sessionCache["personaName"] = onlineId;
        _sessionCache["LKEY"] = _sharedCounters.GetNextLkey();
        _sessionCache["UID"] = _sharedCounters.GetNextUserId();

        _sharedCache.AddUserWithKey((string)_sessionCache["LKEY"], (string)_sessionCache["personaName"]);

        var loginResponseData = new Dictionary<string, object>
        {
            { "TXN", "NuPS3Login" },
            { "lkey", _sessionCache["LKEY"] },
            { "userId", _sessionCache["UID"] },
            { "personaName", _sessionCache["personaName"] }
        };

        var loginPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, loginResponseData);
        var loginResponse = await loginPacket.Serialize();

        _network.WriteApplicationData(loginResponse.AsSpan());
    }

    private async Task HandleAddAccount(Packet request)
    {
        var data = new Dictionary<string, object>
        {
            {"TXN", "NuPS3AddAccount"}
        };

        var email = request.DataDict["nuid"] as string;
        var pass = request.DataDict["password"] as string;

        _logger.LogDebug("Trying to register user {email} with password {pass}", email, pass);

        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    private Task HandleMemCheck()
    {
        return Task.CompletedTask;
    }

    private async Task SendMemCheck()
    {
        var memCheckData = new Dictionary<string, object>
                {
                    { "TXN", "MemCheck" },
                    { "memcheck.[]", "0" },
                    { "type", "0" },
                    { "salt", PacketUtils.GenerateSalt() }
                };

        // FESL backend is requesting the client to respond to the memcheck, so this is a request
        // But since memchecks are not part of the meaningful conversation with the client, they don't have a packed id
        var memcheckPacket = new Packet("fsys", FeslTransmissionType.SinglePacketRequest, 0, memCheckData);
        var memcheckResponse = await memcheckPacket.Serialize();

        _network.WriteApplicationData(memcheckResponse.AsSpan());
    }

    //ModifySettings
    private async Task HandleModifySettings(Packet request)
    {

        var data = new Dictionary<string, object>
        {
            {"TXN", "ModifySettings"}
        };


        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    //HandleGameSpyPreAuth
    private async Task HandleGameSpyPreAuth(Packet request)
    {
        var data = new Dictionary<string, object>
        {
            {"TXN", "GameSpyPreAuth"},
            {"challenge", "test"}
        };


        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    //GetAccount
    private async Task HandleGetAccount(Packet request)
    {
        const string keyTempl = "W5NyZzx{0}Cki6GQAAKDw.";
        var lkey = string.Format(keyTempl, "SaUr4131g");

        var data = new Dictionary<string, object>
        {
            {"lkey", lkey},
            {"TXN", "GetAccount"},
            {"countryDesc", "\"United States of America\""},
            {"thirdPartyMailFlag", "1"},
            {"dobMonth", "6"},
            {"dobYear", "1989"},
        };


        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    //LoginSubAccount
    private async Task HandleLoginSubAccount(Packet request)
    {
        const string keyTempl = "W5NyZzx{0}Cki6GQAAKDw.";
        var lkey = string.Format(keyTempl, "SaUr4131g");

        var data = new Dictionary<string, object>
        {
            {"lkey", lkey},
            {"TXN", "LoginSubAccount"},
            {"subAccounts.1", "bob"},
            {"userId", 1000000000000},
            {"profileId", 1000000000000},
            {"displayName", "bob"}
        };


        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    //HandleNuGetPersonas
    private async Task HandleNuGetPersonas(Packet request)
    {
        var data = new Dictionary<string, object>
        {
            {"personas.0", "bob"}
        };


        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }


    //NuLoginPersona
    private async Task HandleNuLoginPersona(Packet request)
    {
        const string keyTempl = "W5NyZzx{0}Cki6GQAAKDw.";
        var lkey = string.Format(keyTempl, "SaUr4131g");

        var data = new Dictionary<string, object>
        {
            {"TXN", "NuLoginPersona"},
            {"lkey", lkey},
            {"userId", 1000000000000},
            {"profileId", 1000000000000}
        };


        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    //HandleGetSubAccounts
    private async Task HandleGetSubAccounts(Packet request)
    {
        const string keyTempl = "W5NyZzx{0}Cki6GQAAKDw.";
        var lkey = string.Format(keyTempl, "SaUr4131g");

        var data = new Dictionary<string, object>
        {
            {"TXN", "GetSubAccounts"},
            {"lkey", lkey},
            {"subAccounts.1", "bob"},
            {"subAccounts.[]", 1}
        };

        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }


    private async Task HandleLogin3(Packet request)
    {
        const string keyTempl = "W5NyZzx{0}Cki6GQAAKDw.";
        var lkey = string.Format(keyTempl, "SaUr4131g");

        var data = new Dictionary<string, object>
        {
            {"TXN", "NuLogin"},
            {"lkey", lkey},
            {"userId", 1000000000000},
            {"profileId", 1000000000000},
            {"displayName", "bob"}
        };

        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    //NuGetEntitlements
    private async Task HandleNuGetEntitlements(Packet request)
    {
        var group = request.DataDict.TryGetValue("groupName", out var groupName);
        _logger.LogTrace("groupName: {0}", groupName);

        var data = new Dictionary<string, object>
        {
            {"TXN", "NuGetEntitlements"},
            {"entitlements.[]", 0}
        };

        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    //GetLockerURL
    private async Task HandleGetLockerURL(Packet request)
    {

        var data = new Dictionary<string, object>
        {
            {"TXN", "GetLockerURL"},
            {"URL", "http://127.0.0.1/test.php"}
        };

        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    //GetRecordAsMap
    private async Task HandleGetRecordAsMap(Packet request)
    {
        var data = new Dictionary<string, object>
        {
            {"TXN", "GetRecordAsMap" },
            {"localizedMessage", "\"Record not found\""},
            {"errorContainer.[]", 0},
            {"errorCode", 5000}
        };

        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    //GetRecord
    private async Task HandleGetRecord(Packet request)
    {
        var data = new Dictionary<string, object>
        {
            {"TXN", "GetRecord" },
            {"localizedMessage", "\"Record not found\""},
            {"errorContainer.[]", 0},
            {"errorCode", 5000}
        };

        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    //GetMessages
    private async Task HandleGetMessages(Packet request)
    {
        var data = new Dictionary<string, object>
        {
            {"TXN", "GetMessages" },
            {"localizedMessage", "\"Record not found\""},
            {"messages.[]", 0}
        };

        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }

    private async Task HandleLogin2(Packet request)
    {
        const string keyTempl = "W5NyZzx{0}Cki6GQAAKDw.";
        var lkey = string.Format(keyTempl, "SaUr4131g");

        var data = new Dictionary<string, object>
        {
            {"TXN", "Login"},
            {"lkey", lkey},
            {"userId", 1000000000000},
            {"profileId", 1000000000000},
            {"displayName", "bob"}
        };

        var resultPacket = new Packet("acct", FeslTransmissionType.SinglePacketResponse, request.Id, data);
        var response = await resultPacket.Serialize();

        _network.WriteApplicationData(response.AsSpan());
    }
}