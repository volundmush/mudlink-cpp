//
// Created by volund on 5/9/21.
//

#include "mudlink/websocket.hpp"

namespace mudlink::websocket {
    // WebSocketMudConnection
    WebSocketMudConnection::WebSocketMudConnection(MudListener &l, uint32_t id) : MudConnection(l, id) {};

    void WebSocketMudConnection::onPlainConnect() {
        auto old = conn.peer;
        conn.websocket = new TcpWebSocket(std::move(*old));
        wsock = true;
        delete old;
        conn.websocket->async_accept([&](std::error_code ec){
            if(!ec) {
                start();
            }});
    }

    void WebSocketMudConnection::onSecureConnect() {
        auto old = conn.secure_peer;
        conn.tls_websocket = new TlsWebSocket(std::move(*old));
        wsock = true;
        delete old;
        conn.tls_websocket->async_accept([&](std::error_code ec){
            if(!ec) {
                start();
            }});
    }

    MudConnectionType WebSocketMudConnection::getType() {
        return WebSocket;
    }

    void WebSocketMudConnection::start() {
        std::cout << "websocket is running!" << std::endl;
    }

    void WebSocketMudConnection::send() {
        if (!isWriting) {
            if (outbox.size() > 0) {
                isWriting = true;
                // code here!
            }
        }
    }

    void WebSocketMudConnection::receive() {
        auto handler = [&](std::error_code ec, std::size_t length){
            if(!ec) {
                std::cout << "Got some WebSocket bytes: " << length << std::endl;
                onReceive();
                receive();
            }
        };
        if(isTLS()) {
            conn.tls_websocket->async_read(inbox, handler);
        } else {
            conn.websocket->async_read(inbox, handler);
        }
    }

    void WebSocketMudConnection::onReceive() {

    }
}