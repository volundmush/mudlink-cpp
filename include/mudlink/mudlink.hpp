//
// Created by volund on 11/27/20.
//

#ifndef MUDLINK_MUDLINK_H
#define MUDLINK_MUDLINK_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <cstdint>
#include <list>
#include <optional>
#include <memory>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/interprocess/streams/bufferstream.hpp>
#include <boost/algorithm/string/trim.hpp>

class MudLink;
class MudListener;

using TcpSocket = boost::asio::ip::tcp::socket;
using TlsSocket = boost::beast::ssl_stream<TcpSocket>;
using TcpWebSocket = boost::beast::websocket::stream<TcpSocket>;
using TlsWebSocket = boost::beast::websocket::stream<TlsSocket>;


enum MudConnectionType : uint8_t {
    Telnet = 0,
    WebSocket = 1
};

union MudConn {
    TcpSocket* peer;
    TlsSocket* secure_peer;
    TcpWebSocket* websocket;
    TlsWebSocket* tls_websocket;
};

class MudConnection {
public:
    explicit MudConnection(MudListener& l, uint32_t id);
    virtual ~MudConnection();
    void onConnect();
    virtual void receive() = 0;
    virtual void onReceive() = 0;
    virtual void send() = 0;
    virtual void onPlainConnect() = 0;
    virtual void onSecureConnect() = 0;
    bool isTLS() const;
    virtual void start() = 0;
    void onReady();
    virtual MudConnectionType getType() = 0;
    bool isWriting = false;
    uint32_t conn_id;
    boost::asio::ip::address address;
    boost::asio::io_context& context;
    MudListener& listener;
    boost::asio::streambuf inbox, outbox;
    MudConn conn;
    bool wsock = false;
    // callback data

    std::optional<std::function<void()>> onDisconnectCB;
    std::optional<std::function<void(std::string)>> onCommandCB;
    std::optional<std::function<void()>> onUpdateCB;
    std::optional<std::function<void()>> onMSDPCB;

};

enum TelnetMsgType : uint8_t {
    AppData = 0,
    Command = 1,
    Negotiation = 2,
    Subnegotiation = 3
};

struct TelnetMessage {
    TelnetMsgType msg_type;
    std::string data;
    uint8_t codes[2];
};

enum TelnetCode : uint8_t {
    NUL = 0,
    BEL = 7,
    CR = 13,
    LF = 10,
    SGA = 3,
    TELOPT_EOR = 25,
    NAWS = 31,
    LINEMODE = 34,
    EOR = 239,
    SE = 240,
    NOP = 241,
    GA = 249,
    SB = 250,
    WILL = 251,
    WONT = 252,
    DO = 253,
    DONT = 254,
    IAC = 255,

    // MNES: Mud New-Environ Standard
    MNES = 39,

    // MXP: MUD eXtension Protocol
    MXP = 91,

    // MSSP: Mud Server Status Protocol
    MSSP = 70,

    // MCCP#: Mud Client Compression Protocol
    // Not gonna support these.
    MCCP2 = 86,
    MCCP3 = 87,

    // GMCP: Generic Mud Communication Protocol
    GMCP = 201,

    // MSDP: Mud Server Data Protocol
    MSDP = 69,

    // TTYPE - Terminal Type
    TTYPE = 24

};

struct TelnetOptionPerspective {
    bool enabled = false, negotiating = false, answered = false;
};

class TelnetHandshakeHolder;
class TelnetOption;

class TelnetMudConnection : public MudConnection {
public:
    TelnetMudConnection(MudListener& l, uint32_t id);
    void onPlainConnect() override;
    void onSecureConnect() override;
    void start() override;
    void send() override;
    void receive() override;
    void onReceive() override;
    void onReceiveMessage(TelnetMessage *msg);
    void onReceiveAppData(TelnetMessage *msg);
    void onReceiveNegotiation(TelnetMessage *msg);
    void onReceiveSubnegotiation(TelnetMessage *msg);
    void onReceiveCommand(TelnetMessage *msg);
    void sendNegotiate(TelnetCode command, TelnetCode opcode);
    void registerOption(TelnetOption *op);
    void checkReady();
    void finishReady();
    MudConnectionType getType() override;
    std::string cmdbuff;
    TelnetHandshakeHolder *hs_local, *hs_remote, *hs_special;
    std::unordered_map<uint8_t, TelnetOption*> options;
    boost::asio::high_resolution_timer timer;
    bool started = false;
};

class TelnetOption {
public:
    TelnetOption(TelnetMudConnection *connection);
    virtual TelnetCode opCode() = 0;
    virtual bool startWill(), startDo(), supportLocal(), supportRemote();
    virtual void registerHandshake();
    virtual void onConnect(), enableLocal(), enableRemote(), disableLocal(), disableRemote();
    void negotiate(TelnetCode command);
    void receiveNegotiate(TelnetCode command);
    void receiveSubnegotiate(std::string& data);
    virtual void rejectLocalHandshake(), acceptLocalHandshake(), rejectRemoteHandshake(), acceptRemoteHandshake();
    TelnetOptionPerspective local, remote;
    TelnetMudConnection *conn;
};

class MXPOption : public TelnetOption {
public:
    MXPOption(TelnetMudConnection *connection);
    TelnetCode opCode() override;
};

class TelnetHandshakeHolder {
public:
    TelnetHandshakeHolder(TelnetMudConnection *connection);
    std::unordered_set<TelnetCode> handshakes;
    void registerHandshake(TelnetCode code);
    void processHandshake(TelnetCode code);
    bool empty();
    TelnetMudConnection *conn;
};

class WebSocketMudConnection : public MudConnection {
public:
    WebSocketMudConnection(MudListener& l, uint32_t id);
    void onPlainConnect() override;
    void onSecureConnect() override;
    void start() override;
    void send() override;
    void receive() override;
    void onReceive() override;
    MudConnectionType getType() override;
};

class MudListener {
public:
    MudListener(MudLink& link, std::string& name, MudConnectionType type, boost::asio::ip::address& addr, uint16_t port,
                boost::asio::ssl::context* ssl_context);
    void listen();
    void start();
    void stop();
    MudLink& link;
    MudConnectionType type;
    boost::asio::io_context& context;
    boost::asio::ssl::context* ssl_con;
    bool running;
    std::string name;
    boost::asio::ip::address& address;
    uint16_t port;
private:
    boost::asio::ip::tcp::acceptor acceptor;
};

class MudLink {
public:
    MudLink(boost::asio::io_context& io_con);
    void registerSSL(std::string name);
    void registerAddress(std::string name, std::string addr);
    void registerListener(std::string name, std::string address, uint16_t port, MudConnectionType type,
                          std::optional<std::string> ssl_name);
    void startListening();
    void stopListening();
    boost::asio::io_context& context;
    std::unordered_map<std::string, MudListener*> listeners;
    uint32_t nextId = 0;
    std::unordered_map<std::string, boost::asio::ip::address> addresses;
    std::unordered_map<std::string, boost::asio::ssl::context*> ssl_contexts;
    std::unordered_map<uint32_t, MudConnection*> connections, pending;
    // callbacks
    std::optional<std::function<void(MudConnection*)>> onConnectCB;

};

#endif //MUDLINK_MUDLINK_H
