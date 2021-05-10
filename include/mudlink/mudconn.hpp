//
// Created by volund on 5/9/21.
//

#ifndef MUDLINK_MUDCONN_H
#define MUDLINK_MUDCONN_H

#include <cstdint>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/ssl/ssl_stream.hpp>
#include <boost/interprocess/streams/bufferstream.hpp>
#include <iostream>
#include <unordered_map>
#include <unordered_set>
#include <any>
#include <deque>
#include <thread>
#include <mutex>

namespace mudlink {
    using TcpSocket = boost::asio::ip::tcp::socket;
    using TlsSocket = boost::beast::ssl_stream<TcpSocket>;
    using TcpWebSocket = boost::beast::websocket::stream<TcpSocket>;
    using TlsWebSocket = boost::beast::websocket::stream<TlsSocket>;

    enum ProtocolType : uint8_t {
        Telnet = 0,
        WebSocket = 1
    };

    union MudConn {
        TcpSocket* peer;
        TlsSocket* secure_peer;
        TcpWebSocket* websocket;
        TlsWebSocket* tls_websocket;
    };

    enum MudColor : uint8_t {
        None = 0,
        Ansi = 1,
        Xterm = 2,
        TrueColor = 3
    };

    enum ToMudEvent : uint8_t {
        Command = 0,
        OOB = 1,
        StatusReq = 2,
        Update = 3,
        Disconnected = 4,
        Ready = 5
    };

    struct MsgToMud {
        ToMudEvent mtype;
        std::any data;
    };

    enum FromMudEvent : uint8_t {
        Line = 0,
        Text = 1,
        Prompt = 2,
        OobData = 3,
        MSSP = 4,
        Disconnect = 5,
    };

    struct MsgFromMud {
        FromMudEvent mtype;
        std::any data;
    };

    struct Capabilities {
        ProtocolType protocol;
        std::string client_name, client_version;
        MudColor color;
        bool utf8, mxp, oob, msdp, gmcp, mssp, mtts, naws, mccp2, sga = true, linemode = true;
        bool screen_reader, vt100, mouse_tracking, osc_color_palette, mnes, proxy;
    };

    struct ConnQueue;

    struct MudConnection {
        explicit MudConnection(ConnQueue &cq, uint32_t id);
        virtual ~MudConnection();
        void onConnect();
        virtual void send();
        virtual void receive();
        virtual void onPlainConnect();
        virtual void onSecureConnect();
        void sendToMud(MsgToMud &m);
        virtual void start() = 0;
        virtual void onReceive() = 0;
        virtual void processFromMud(MsgFromMud &ev) = 0;
        [[nodiscard]] bool isTLS() const;
        void onReady();
        Capabilities cap;
        boost::asio::ssl::context* scon = nullptr;
        bool isWriting = false, wsock = false, active = false;
        uint32_t conn_id;
        boost::asio::ip::address address;
        std::vector<MsgToMud> pending_events;
        boost::asio::streambuf inbox, outbox;
        std::deque<MsgFromMud> out_events;
        std::deque<MsgToMud> in_events;
        std::mutex in_mut, out_mut;
        MudConn conn;
        ConnQueue& cqueue;
    };

    struct ConnQueue {
        explicit ConnQueue(boost::asio::io_context& con);
        bool send(uint32_t id, MsgFromMud &ev);
        void processOutEvents();
        std::mutex mut;
        boost::asio::io_context& io_con;
        std::unordered_map<uint32_t, MudConnection*> connections, in_ready, out_ready;
    };

}

#endif //MUDLINK_MUDCONN_H
