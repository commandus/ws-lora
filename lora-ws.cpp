#include <string>
#include <cstring>
#include <functional>
#include <bitset>

#include <microhttpd.h>
#include <sstream>
#include <iostream>

#include "base64/base64.h"

#include "lorawan/lorawan-string.h"
#include "lorawan/helper/key128gen.h"
#include "lorawan/proto/gw/basic-udp.h"
#include "lorawan/storage/serialization/urn-helper.h"


static const std::string VERSION_STR("1.0");

// Caution: version may be different, if microhttpd dependency not compiled, revise version humber
#if MHD_VERSION <= 0x00096600
#define MHD_Result int
#endif
#ifndef MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS "Access-Control-Allow-Credentials"
#endif
#ifndef MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS "Access-Control-Allow-Methods"
#endif
#ifndef MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS "Access-Control-Allow-Headers"
#endif
#ifndef MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN
#define MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN "Access-Control-Allow-Origin"
#endif

#define	LOG_ERR								3
#define	LOG_INFO							5

#include "lora-ws.h"
#include "lorawan/lorawan-conv.h"
#include "nayuki/qrcodegen.hpp"
#include "lorawan/storage/serialization/qr-helper.h"

#define PATH_COUNT 2

enum class RequestType {
    REQUEST_TYPE_VERSION = 0,
    REQUEST_TYPE_CLAUSE = 1,
    REQUEST_TYPE_UNKNOWN = 100
};

enum class RET_MIME_TYPE {
    RET_MIME_TYPE_JSON = 0,
    RET_MIME_TYPE_SVG = 1,
    RET_MIME_TYPE_ERROR = 100
};

class RequestContext {
public:
    RequestType requestType;
    std::string postData;
    RequestContext()
        : requestType(RequestType::REQUEST_TYPE_UNKNOWN) {
    }
};

static const char *paths[PATH_COUNT] = {
    "/version",
    "/clause"
};

const static char *CT_JSON = "text/javascript;charset=UTF-8";
const static char *CT_SVG = "image/svg+xml";

const static char *HDR_CORS_ORIGIN = "*";
const static char *HDR_CORS_METHODS = "GET,HEAD,OPTIONS,POST,PUT,DELETE";
const static char *HDR_CORS_HEADERS = "Authorization, Access-Control-Allow-Headers, Access-Control-Allow-Origin, "
    "Origin, Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers";

const static char *MSG_HTTP_ERROR = "Error";
const static char *MSG401 = "Unauthorized";
const static char *MSG501 = "Not implemented";

const static char *MSG500 = "Internal server error";

static RequestType parseRequestType(const char *url)
{
	int i;
	for (i = 0; i < PATH_COUNT; i++) {
		if (strstr(paths[i], url))
			return (RequestType) i;
	}
	return RequestType::REQUEST_TYPE_UNKNOWN;
}

void *uri_logger_callback(
    void *cls,
    const char *uri
)
{
    auto c = (WSConfig *) cls;
    if (c->verbosity && (!c->daemonize)) {
        std::cout << uri << std::endl;
    }
	return nullptr;
}

static void jsInvalidParametersCount(
    std::ostream &retVal,
    const std::vector<QueryParam> &params
) {
    retVal << "{\"code\": -5001, \"error\": \"Invalid parameters\", \"count\": " << params.size() << "}";
}

static void jsInvalidParameterValue(
    std::ostream &retVal
) {
    retVal << "{\"code\": -5002, \"error\": \"Invalid parameter value\"}";
}

static void jsVersion(
    std::ostream &retval
)
{
    retval << "{\"version\": \"" << VERSION_STR << "\"}";
}

static std::string addr2bin(
    const DEVADDR &value
)
{
    std::stringstream r;
    r << std::bitset<8>{value.c[3]}.to_string()
        << std::bitset<8>{value.c[2]}.to_string()
        << std::bitset<8>{value.c[1]}.to_string()
        << std::bitset<8>{value.c[0]}.to_string();
    return r.str();    
}

static void addrBitExplanation(
    std::ostream &retVal,
    const DEVADDR &value,
    const std::string &prefix = ""
)
{
    std::stringstream ss;
    uint8_t typ = value.getNetIdType();
    uint8_t prefixLen = DEVADDR::getTypePrefixBitsCount(typ);
    uint8_t nwkIdLen = DEVADDR::getNwkIdBitsCount(typ);
    uint8_t nwkAddrLen = DEVADDR::getNwkAddrBitsCount(typ);

    retVal
        << "\"" << prefix << "binary\": \"" << addr2bin(value)
        << "\",\"" << prefix << "prefixlen\": " << (int) prefixLen
        << ",\"" << prefix << "nwkidlen\": " << (int) nwkIdLen
        << ",\"" << prefix << "addrlen\": " << (int) nwkAddrLen;
}

static void jsNetId(
    std::ostream &retVal,
    const DEVADDR &addr
) {
    NETID nid(addr.getNetIdType(), addr.getNwkId());
    DEVADDR minAddr(nid, false);
    DEVADDR maxAddr(nid, true);

    retVal << "{\"addr\": \"" << DEVADDR2string(addr)
        << "\", \"netid\": \"" << nid.toString()
        << "\", \"type\": " << (int) nid.getType()
        << ", \"id\": \"" << std::hex << nid.getNetId()
        << "\", \"nwkId\": \"" << std::hex << nid.getNwkId()
        << "\", " << std::dec;
    addrBitExplanation(retVal, addr);
    retVal
        << std::hex << R"(, "addrMin": ")" << minAddr.toString()
        << "\", " << std::dec;
    addrBitExplanation(retVal, minAddr, "min");
    retVal
        << std::hex << R"(, "addrMax": ")" << maxAddr.toString()
        << "\", " << std::dec;
    addrBitExplanation(retVal, maxAddr, "max");
    retVal << "}";
}

static void jsAddrs(
    std::ostream &retVal,
    uint8_t &netTypeId,
    uint32_t &nwkId
) {
    DEVADDR minAddr(netTypeId, nwkId, 0);
    NETID nid(minAddr.getNetIdType(), minAddr.getNwkId());
    DEVADDR maxAddr(nid, true);
    
    retVal << R"({"addr": ")" << DEVADDR2string(minAddr)
        << R"(", "netid": ")" << nid.toString()
        << R"(", "type": )" << (int) nid.getType()  // << "\", \"type\": " << (int) minAddr.getNetIdType()
        << ", \"id\": \"" << std::hex << nid.getNetId()
        << R"(", "nwkId": ")" << std::hex << nid.getNwkId()
        << "\", " << std::dec;
    addrBitExplanation(retVal, minAddr);
    retVal
        << std::hex << R"(, "addrMin": ")" << minAddr.toString()
        << "\", " << std::dec;
    addrBitExplanation(retVal, minAddr, "min");
    retVal
        << std::hex << R"(, "addrMax": ")" << maxAddr.toString()
        << "\", " << std::dec;
    addrBitExplanation(retVal, maxAddr, "max");
    retVal << "}";
}

static void jsGwPushData(
    std::ostream &retVal,
    GwPushData &value
) {
    retVal << "{\"rxMetadata\": "
       << SEMTECH_PROTOCOL_METADATA_RX2string(value.rxMetadata)
       << ", \"rxData\": " << value.rxData.toString()
       << "}";
}

static void jsGw(
    std::ostream &retVal,
    const std::string &packetForwarderPacket
) {
    size_t size = packetForwarderPacket.size();
    if (size <= sizeof(SEMTECH_PREFIX)) {   // at least 4 bytes
        jsInvalidParameterValue(retVal);
        return;
    }
    auto *p = (SEMTECH_PREFIX *) packetForwarderPacket.c_str();
    if (p->version != 2) {
        jsInvalidParameterValue(retVal);
        return;
    }

    int r;
    switch (p->tag) {
        case SEMTECH_GW_PUSH_DATA:  // 0 network server responds on PUSH_DATA to acknowledge immediately all the PUSH_DATA packets received
        {
            auto *pGw = (SEMTECH_PREFIX_GW *) packetForwarderPacket.c_str();
            ntoh_SEMTECH_PREFIX_GW(*pGw);
            GwPushData gwPushData;
            TASK_TIME receivedTime = std::chrono::system_clock::now();
            r = parsePushData(&gwPushData, (char *) packetForwarderPacket.c_str() + SIZE_SEMTECH_PREFIX_GW,
                size - SIZE_SEMTECH_PREFIX_GW, pGw->mac, receivedTime); // +12 bytes
            if (!r)
                retVal << "{\"metadata\": " << SEMTECH_PROTOCOL_METADATA_RX2string(gwPushData.rxMetadata)
                    << ", \"rfm\": " << gwPushData.rxData.toString()
                    << "}";
        }
            break;
        case SEMTECH_GW_PULL_RESP:  // 4
        {
            auto *pGw = (SEMTECH_PREFIX_GW *) packetForwarderPacket.c_str();
            ntoh_SEMTECH_PREFIX_GW(*pGw);
            GwPullResp gwPullResp;
            r = parsePullResp(&gwPullResp, (char *) packetForwarderPacket.c_str() + SIZE_SEMTECH_PREFIX,
                size - SIZE_SEMTECH_PREFIX, pGw->mac); // +4 bytes
            if (!r)
                retVal
                    << "{\"gwId\": \"" << DEVEUI2string(gwPullResp.gwId)
                    << "\", \"metadata\": " << SEMTECH_PROTOCOL_METADATA_TX2string(gwPullResp.txMetadata)
                    << ", \"rfm\": " << gwPullResp.txData.toString()
                    << "}";
        }
            break;
        case SEMTECH_GW_TX_ACK:     // 5 gateway inform network server about does PULL_RESP data transmission was successful or not
        {
            ERR_CODE_TX code;
            r = parseTxAck(&code, (char *) packetForwarderPacket.c_str() + SIZE_SEMTECH_PREFIX_GW,
                SIZE_SEMTECH_PREFIX_GW); // +12 bytes
            if (!r)
                retVal
                    << "{\"code\": \"" << ERR_CODE_TX2string(code)
                    << "\"}";
        }
            break;
        default:
            jsInvalidParameterValue(retVal);
            return;
    }
}

static void jsRfm(
    std::ostream &retVal,
    std::string &value
) {
    auto *rfm = (RFM_HEADER *) value.c_str();
    size_t sz = value.size();
    if (sz < SIZE_RFM_HEADER) {
        jsInvalidParameterValue(retVal);
        return;
    }
    ntoh_RFM_HEADER(rfm);
    retVal
        << R"({"mhdr": {"mtype": )" << (int) rfm->macheader.f.mtype
        << R"(, "major": )" << (int) rfm->macheader.f.major
        << ", \"rfu\": " << (int) rfm->macheader.f.rfu
        << R"(}, "addr": ")" << DEVADDR2string(rfm->fhdr.devaddr)
        << R"(", "fctrl": {"foptslen": )"
        << (unsigned int) rfm->fhdr.fctrl.f.foptslen;
    if ((rfm->macheader.f.mtype == MTYPE_UNCONFIRMED_DATA_DOWN) || (rfm->macheader.f.mtype == MTYPE_CONFIRMED_DATA_DOWN)) {
        retVal << ", \"pending\": " << ((unsigned int) rfm->fhdr.fctrl.f.fpending == 0 ? "false": "true");
    }
    if ((rfm->macheader.f.mtype == MTYPE_UNCONFIRMED_DATA_UP) || (rfm->macheader.f.mtype == MTYPE_CONFIRMED_DATA_UP)) {
        retVal << ", \"classB\": " << ((unsigned int) rfm->fhdr.fctrl.fup.classb == 0 ? "false": "true")
            << ", \"addrackreq\": " << (rfm->fhdr.fctrl.fup.addrackreq == 0 ? "false" : "true");
    }
    retVal << ", \"ack\": " << ((unsigned int) rfm->fhdr.fctrl.f.ack == 0 ? "false": "true")
        << ", \"adr\": " << (rfm->fhdr.fctrl.f.adr == 0 ? "false" : "true")
        << "}, \"fcnt\": "  << rfm->fhdr.fcnt;

    if (rfm->fhdr.fctrl.f.foptslen && sz - SIZE_RFM_HEADER > rfm->fhdr.fctrl.f.foptslen) {
        retVal << R"(, "mac": ")" << hexString((value.c_str() + SIZE_RFM_HEADER), rfm->fhdr.fctrl.f.foptslen)
               << "\"";
    }
    if (sz < SIZE_RFM_HEADER + rfm->fhdr.fctrl.f.foptslen)
        return; // no FPort, no FRMPayload
    std::string payload = std::string(value.c_str() + SIZE_RFM_HEADER + rfm->fhdr.fctrl.f.foptslen + 1,
        sz - SIZE_RFM_HEADER - rfm->fhdr.fctrl.f.foptslen - 1 - 4); // except MIC
    retVal << ", \"fport\": " << (unsigned int) *((uint8_t*) value.c_str() + SIZE_RFM_HEADER + rfm->fhdr.fctrl.f.foptslen)
        << R"(, "payload": ")" << hexString(payload)
        << "\", \"mic\": \"" << std::hex << std::setw(8) << std::setfill('0') << NTOH4(*((uint32_t *) ((uint8_t *) value.c_str() + value.size() - 4)))
        << "\"}";
}

static void jsKeyGen(
    std::ostream &retVal,
    const std::string &masterKey,
    const DEVADDR &addr
) {
    // generate "master key" by the passphrase
    KEY128 phraseKey;
    phrase2key((uint8_t *) &phraseKey.c, masterKey.c_str(), masterKey.size());

    // generate EUI
    DEVEUI eui;
    euiGen((uint8_t *) &eui.c, KEY_NUMBER_EUI, (uint8_t *) &phraseKey.c, addr.u);
    KEY128 nwkKey;
    keyGen((uint8_t *) &nwkKey.c, KEY_NUMBER_NWK, (uint8_t *) &phraseKey.c, addr.u);
    KEY128 appKey;
    keyGen((uint8_t *) &appKey.c, KEY_NUMBER_APP, (uint8_t *) &phraseKey.c, addr.u);
    retVal << R"({"addr": ")" << DEVADDR2string(addr)
        << R"(", "eui": ")" << DEVEUI2string(eui)
        << R"(", "nwkKey": ")" << KEY2string(nwkKey)
        << R"(", "appKey": ")" << KEY2string(appKey)
        << "\"}";
}

static void printClass
(
    std::ostream &retVal,
    const NETID &netid1,
    const NETID &netid2
) {
    DEVADDR minAddr1(netid1, false);
    DEVADDR maxAddr1(netid1, true);
    DEVADDR minAddr2(netid2, false);
    DEVADDR maxAddr2(netid2, true);
    uint8_t typ = minAddr1.getNetIdType();
    uint8_t prefixLen = DEVADDR::getTypePrefixBitsCount(typ);
    uint8_t nwkIdLen = DEVADDR::getNwkIdBitsCount(typ);
    uint8_t nwkAddrLen = DEVADDR::getNwkAddrBitsCount(typ);
    retVal
        << "{\"type\": " << (int) netid1.getType()
        << R"(, "nwkMin": ")" << std::hex << netid1.getNwkId()
        << R"(", "nwkMax": ")" << netid2.getNwkId()
        << R"(", "nwkMinAddrMin": ")" << minAddr1.toString()
        << R"(", "nwkMinAddrMax": ")" << maxAddr1.toString()
        << R"(", "nwkMaxAddrMin": ")" << minAddr2.toString()
        << R"(", "nwkMaxAddrMax": ")" << maxAddr2.toString()
        << R"(", "prefixlen": )" << std::dec << (int) prefixLen
        << ", \"" << "nwkidlen\": " << (int) nwkIdLen
        << ", \"" << "addrlen\": " << (int) nwkAddrLen << "}";
}

static void jsAllClasses(
    std::ostream &retVal
) {
    NETID netid;
    NETID netid2;
    // print header
    retVal 
        << "[";
        
    netid.set(0, 0);\
    netid2.set(0, (1 << 6) - 1);
    printClass(retVal, netid, netid2);
    retVal << ", \n";
    
    netid.set(1, 0);
    netid2.set(1, (1 << 6) - 1);
    printClass(retVal, netid, netid2);
    retVal << ", \n";

    netid.set(2, 0);
    netid2.set(2, (1 << 9) - 1);
    printClass(retVal, netid, netid2);
    retVal << ", \n";
    
    netid.set(3, 0);
    netid2.set(3, (1 << 21) - 1);
    printClass(retVal, netid, netid2);
    retVal << ", \n";
    
    netid.set(4, 0);
    netid2.set(4, (1 << 21) - 1);
    printClass(retVal, netid, netid2);
    retVal << ", \n";
    
    netid.set(5, 0);
    netid2.set(5, (1 << 21) - 1);
    printClass(retVal, netid, netid2);
    retVal << ", \n";
    
    netid.set(6, 0);
    netid2.set(6, (1 << 21) - 1);
    printClass(retVal, netid, netid2);
    retVal << ", \n";
    
    netid.set(7, 0);
    netid2.set(7, (1 << 21) - 1);
    printClass(retVal, netid, netid2);
    retVal << "]";
}

static void jsUrn(
    std::ostream &retVal,
    const std::string &join_eui,            // 16 hex digits
    const std::string &dev_eui,             // 16 hex digits
    const std::string &profile_id,          // 8 hex digits
    const std::string &owner_token,
    const std::string &serial_number,
    const std::string &proprietary,
    bool addCheckSum
)
{
    DEVEUI joinEui;
    string2DEVEUI(joinEui, join_eui);
    DEVEUI devEui;
    string2DEVEUI(devEui, dev_eui);
    PROFILEID profileId(profile_id);
    std::vector<std::string> extraProprietary;
    if (!proprietary.empty())
        extraProprietary.push_back(proprietary);

    std::string r = mkURN(joinEui, devEui, profileId,
        owner_token, serial_number, &extraProprietary, addCheckSum);
    retVal << "\"" << r << "\"";
}

static void jsQr(
    std::ostream &retVal,
    const std::string &join_eui,            // 16 hex digits
    const std::string &dev_eui,             // 16 hex digits
    const std::string &profile_id,          // 8 hex digits
    const std::string &owner_token,
    const std::string &serial_number,
    const std::string &proprietary,
    bool addCheckSum
)
{
    std::stringstream ss;
    jsUrn(ss, join_eui, dev_eui,
        profile_id, owner_token, serial_number, proprietary, addCheckSum);
    std::string urn = ss.str();
    const qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(urn.c_str(), qrcodegen::QrCode::Ecc::LOW);
    retVal << qrCode2Svg(qr, 1);
}

static RET_MIME_TYPE fetchResponse(
    std::ostream &retVal,
    const WSConfig *config,
    const RequestContext *env
)
{
    // grpc::ServerContext svcContext;
	switch (env->requestType) {
        case RequestType::REQUEST_TYPE_VERSION:
            jsVersion(retVal);
            break;
        default:
        {
            std::vector<QueryParam> params;
            QueryParserJson::parse(&params, env->postData);
            if (params.empty()) {
                retVal << "{}";
                return RET_MIME_TYPE::RET_MIME_TYPE_JSON;
            }
            const std::string &f = params[0].s;
            if (f == "netid") {
                if (params.size() < 2) {
                    jsInvalidParametersCount(retVal, params);
                    return RET_MIME_TYPE::RET_MIME_TYPE_ERROR;
                }
                // extract the network identifier from the address
                DEVADDR a;
                string2DEVADDR(a, params[1].s);
                jsNetId(retVal, a);
            } else
                if (f == "addrs") {
                    if (params.size() < 3) {
                        jsInvalidParametersCount(retVal, params);
                        return RET_MIME_TYPE::RET_MIME_TYPE_ERROR;
                    }
                    auto typ = (uint8_t) params[1].i;
                    uint32_t nwkId = 0;
                    if (params[2].t == QUERY_PARAM_INT)
                        nwkId = params[2].i;
                    else
                        nwkId = strtoul(params[2].s.c_str(), nullptr, 16);

                    // extract the network identifier from the address
                    jsAddrs(retVal, typ, nwkId);
                } else
                    if (f == "rfm") {
                        if (params.size() < 2) {
                            jsInvalidParametersCount(retVal, params);
                            return RET_MIME_TYPE::RET_MIME_TYPE_ERROR;
                        }
                        bool isBase64 = false;
                        if (params.size() > 2)
                            isBase64 = params[2].b;
                        std::string s;
                        if (isBase64)
                            s = base64_decode(params[1].s, true);
                        else
                            s = hex2string(params[1].s);
                        jsRfm(retVal, s);
                    } else
                        if (f == "gw") {
                            if (params.size() < 2) {
                                jsInvalidParametersCount(retVal, params);
                                return RET_MIME_TYPE::RET_MIME_TYPE_ERROR;
                            }
                            bool isBase64 = false;
                            if (params.size() > 2)
                                isBase64 = params[2].b;
                            std::string s;
                            if (isBase64)
                                s = base64_decode(params[1].s, true);
                            else
                                s = hex2string(params[1].s);
                            jsGw(retVal, s);
                        } else
                            if (f == "keygen") {
                                if (params.size() < 3) {
                                    jsInvalidParametersCount(retVal, params);
                                    return RET_MIME_TYPE::RET_MIME_TYPE_ERROR;
                                }
                                DEVADDR a;
                                string2DEVADDR(a, params[2].s);
                                jsKeyGen(retVal, params[1].s, a);
                            } else
                                if (f == "version")
                                    jsVersion(retVal);
                                else
                                    if (f == "classes")
                                        jsAllClasses(retVal);
                                    else
                                        if ((f == "urn") || (f == "qr")) {
                                            if (params.size() < 4) {
                                                jsInvalidParametersCount(retVal, params);
                                                return RET_MIME_TYPE::RET_MIME_TYPE_ERROR;
                                            }
                                            // join-eui=16 hex digits, dev-eui=16 hex digits, profile-id=8 hex digits
                                            // owner-token=?, serial-number=?, proprietary=?, 
                                            // CRC-16 = true:false
                                            std::string owner_token;
                                            std::string serial_number;
                                            std::string proprietary;
                                            bool crc;
                                            if (params.size() > 4) {
                                                owner_token = params[4].s;
                                                if (params.size() > 5) {
                                                    serial_number = params[5].s;
                                                    if (params.size() > 6) {
                                                        proprietary = params[6].s;
                                                        if (params.size() > 7) {
                                                            crc = params[7].b;
                                                        }
                                                    }
                                                }
                                            }
                                            if (f == "urn")
                                                jsUrn(retVal, params[1].s, params[2].s, params[3].s,
                                                    owner_token, serial_number, proprietary, crc);
                                            else {
                                                jsQr(retVal, params[1].s, params[2].s, params[3].s,
                                                     owner_token, serial_number, proprietary, crc);
                                                return RET_MIME_TYPE::RET_MIME_TYPE_SVG;
                                            }
                                        } else
                                            retVal << "{}";
        }
            break;
    }
    return RET_MIME_TYPE::RET_MIME_TYPE_JSON;
}

static void addCORS(MHD_Response *response) {
    MHD_add_response_header(response, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, HDR_CORS_ORIGIN);
    // MHD_add_response_header(response, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_CREDENTIALS, HDR_CORS_CREDENTIALS);
    MHD_add_response_header(response, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_METHODS, HDR_CORS_METHODS);
    MHD_add_response_header(response, MHD_HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS, HDR_CORS_HEADERS);
}

static MHD_Result putStringVector(
    void *retVal,
    enum MHD_ValueKind kind,
    const char *key,
    const char *value
)
{
    auto *r = (std::map<std::string, std::string> *) retVal;
    r->insert(std::pair<std::string, std::string>(key, value));
    return MHD_YES;
}

static MHD_Result httpError(
    struct MHD_Connection *connection,
    int code
)
{
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(MSG_HTTP_ERROR), (void *) MSG_HTTP_ERROR, MHD_RESPMEM_PERSISTENT);
    addCORS(response);
    MHD_Result r = MHD_queue_response(connection, code, response);
    MHD_destroy_response(response);
    return r;
}

static MHD_Result httpError401(
    struct MHD_Connection *connection
)
{
    int hc = MHD_HTTP_UNAUTHORIZED;
    struct MHD_Response *response = MHD_create_response_from_buffer(strlen(MSG401), (void *) MSG401, MHD_RESPMEM_PERSISTENT);
    std::string hwa = "Bearer error=\"invalid_token\"";
    MHD_add_response_header(response, MHD_HTTP_HEADER_WWW_AUTHENTICATE, hwa.c_str());
    addCORS(response);
    MHD_Result r = MHD_queue_response(connection, hc, response);
    MHD_destroy_response(response);
    return r;
}

static MHD_Result request_callback(
	void *cls,			// struct WSConfig*
	struct MHD_Connection *connection,
	const char *url,
	const char *method,
	const char *version,
	const char *upload_data,
	size_t *upload_data_size,
	void **ptr
)
{
	struct MHD_Response *response;
	MHD_Result ret;

    if (!*ptr) {
		// do never respond on first call
		*ptr = new RequestContext;
		return MHD_YES;
	}

    if (strcmp(method, "OPTIONS") == 0) {
        response = MHD_create_response_from_buffer(strlen(MSG500), (void *) MSG500, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, CT_JSON);
        addCORS(response);
        MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);
        return MHD_YES;
    }

    auto *requestCtx = (RequestContext *) *ptr;
    if (*upload_data_size != 0) {
        requestCtx->postData += std::string(upload_data, *upload_data_size);
        *upload_data_size = 0;
        return MHD_YES;
    }

    requestCtx->requestType = parseRequestType(url);

    int hc;
    RET_MIME_TYPE r = RET_MIME_TYPE::RET_MIME_TYPE_ERROR;
    if (strcmp(method, "DELETE") == 0) {
        hc = MHD_HTTP_NOT_IMPLEMENTED;
        response = MHD_create_response_from_buffer(strlen(MSG501), (void *) MSG501, MHD_RESPMEM_PERSISTENT);
    } else {
        // Service
        std::stringstream retString;
        r = fetchResponse(retString, (WSConfig *) cls, requestCtx);
        if (r == RET_MIME_TYPE::RET_MIME_TYPE_ERROR) {
            hc = MHD_HTTP_INTERNAL_SERVER_ERROR;
            response = MHD_create_response_from_buffer(strlen(MSG500), (void *) MSG500, MHD_RESPMEM_PERSISTENT);
        } else {
            hc = MHD_HTTP_OK;
            std::string resp = retString.str();
            response = MHD_create_response_from_buffer(resp.size(), (void *) resp.c_str(), MHD_RESPMEM_MUST_COPY);
        }
    }

    if (r == RET_MIME_TYPE::RET_MIME_TYPE_SVG)
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, CT_SVG);
    else
        MHD_add_response_header(response, MHD_HTTP_HEADER_CONTENT_TYPE, CT_JSON);
    addCORS(response);
	ret = MHD_queue_response(connection, hc, response);
	MHD_destroy_response(response);
    delete requestCtx;
    *ptr = nullptr;
	return ret;
}

bool startWS(
	WSConfig &config
) {
	if (config.flags == 0)
		config.flags = MHD_START_FLAGS;

    struct MHD_Daemon *d = MHD_start_daemon(
		config.flags, config.port, nullptr, nullptr,
		&request_callback, &config,
		MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 30,  // 30s timeout
		MHD_OPTION_THREAD_POOL_SIZE, config.threadCount,
		MHD_OPTION_URI_LOG_CALLBACK, &uri_logger_callback, &config,
		MHD_OPTION_CONNECTION_LIMIT, config.connectionLimit,
		MHD_OPTION_END
	);
	config.descriptor = (void *) d;
	return config.descriptor != nullptr;
}

void doneWS(
	WSConfig &config
) {
	if (config.descriptor)
		MHD_stop_daemon((struct MHD_Daemon *) config.descriptor);
	config.descriptor = nullptr;
}
