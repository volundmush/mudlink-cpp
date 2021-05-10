//
// Created by volund on 5/9/21.
//

#include "mudlink/mudconn.hpp"

#include <utility>

namespace mudlink {

    MudConnection::MudConnection(ConnQueue &cq, uint32_t id) : cqueue(cq) {
        this->conn_id = id;
    }

    bool MudConnection::isTLS() const {
        return scon != nullptr;
    }

    void MudConnection::sendToMud(MsgToMud &m) {
        if(active) {
            in_mut.lock();
            in_events.push_back(m);
            in_mut.unlock();
        } else {
            pending_events.push_back(m);
        }
    }

    MudConnection::~MudConnection() {
        if(isTLS()) {
            if(wsock) {
                delete conn.tls_websocket;
            } else {
                delete conn.secure_peer;
            }
        } else {
            if(wsock) {
                delete conn.websocket;
            } else {
                delete conn.peer;
            }
        }
    }

    void MudConnection::onPlainConnect() {
        start();
    }

    void MudConnection::onSecureConnect() {
        start();
    }

    void MudConnection::onConnect() {
        if(isTLS()) {
            auto old = conn.peer;
            conn.secure_peer = new TlsSocket(std::move(*old), *scon);
            delete old;
            conn.secure_peer->async_handshake(boost::asio::ssl::stream_base::server, [&](std::error_code ec){
                if(!ec) {
                    onSecureConnect();
                }});
        } else {
            onPlainConnect();
        }
    }

    void MudConnection::send() {

        if(!isWriting) {
            if(outbox.size() > 0) {
                isWriting = true;
                auto handler = [&](std::error_code ec, std::size_t len){
                    outbox.consume(len);
                    if(outbox.size() > 0) {
                        send();
                    } else {
                        isWriting = false;
                    }
                };
                if(isTLS()) {
                    conn.secure_peer->async_write_some(outbox.data(), handler);
                } else {
                    conn.peer->async_write_some(outbox.data(), handler);
                }
            }
        }
    }

    void MudConnection::receive() {
        auto x = inbox.prepare(1024);
        auto handler = [&](std::error_code ec, std::size_t length) {
            if(!ec) {
                inbox.commit(length);
                onReceive();
                receive();
            } else
            {
                std::cout << "something went wrong" << std::endl << std::flush;
            }
        };
        if(isTLS()) {
            conn.secure_peer->async_read_some(x, handler);
        } else {
            conn.peer->async_read_some(x, handler);
        }
    }

    ConnQueue::ConnQueue(boost::asio::io_context &con) : io_con(con) {

    }

    bool ConnQueue::send(uint32_t id, MsgFromMud &ev) {
        if(connections.contains(id)) {
            mut.lock();
            auto conn = connections[id];
            conn->out_mut.lock();
            conn->out_events.push_back(ev);
            conn->out_mut.unlock();
            out_ready[id] = conn;
            mut.unlock();
            return true;
        } else {
            return false;
        }
    }

    void ConnQueue::processOutEvents() {
        if(out_ready.empty()) {
            return;
        }
        mut.lock();
        std::unordered_set<uint32_t> deleted;
        for(auto c : out_ready) {
            for(auto e : c.second->out_events) {
                switch(e.mtype) {
                    case FromMudEvent::Disconnect:
                        c.second->processFromMud(e);
                        deleted.insert(c.first);
                        break;
                    default:
                        c.second->processFromMud(e);
                        break;
                }
            }
        }
        for(auto d : deleted) {
            in_ready.erase(d);
            out_ready.erase(d);
            auto conn = connections[d];
            delete conn;
            connections.erase(d);
        }
        mut.unlock();

    }

}