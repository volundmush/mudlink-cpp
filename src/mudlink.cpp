//
// Created by volund on 11/27/20.
//

#include "mudlink/mudlink.hpp"
#include "mudlink/telnet.hpp"
#include <iostream>

namespace mudlink {

    MudListener::MudListener(MudLink &lnk, std::string &name, ProtocolType type, boost::asio::ip::address &addr, uint16_t port,
                             boost::asio::ssl::context *ssl_context)
            : link(lnk), address(addr), cqueue(link.cqueue),
              acceptor(link.cqueue.io_con, boost::asio::ip::tcp::endpoint(address, port)) {
        this->name = name;
        this->ptype = type;
        this->port = port;
        running = false;
    }

    void MudListener::start() {
        if(!running) {
            running = true;
            listen();
        }
    }

    void MudListener::stop() {
        if(running) {
            running = false;
        }
    }

    void MudListener::listen() {
        acceptor.async_accept([&](std::error_code ec, TcpSocket sock) {

            if(!ec) {
                MudConnection *mud = nullptr;
                switch(ptype) {
                    case Telnet:
                        mud = new telnet::TelnetConnection(cqueue, link.nextId++);
                        break;
                    case WebSocket:
                        //mud = new WebSocketMudConnection(cqueue, link.nextId++);
                        break;
                }
                mud->address = sock.local_endpoint().address();
                mud->conn.peer = new TcpSocket(std::move(sock));
                mud->onConnect();
            }
            if(running) {
                listen();
            }
        });
    }


    MudLink::MudLink(ConnQueue &cq) : cqueue(cq) {
    }

    void MudLink::registerListener(std::string name, std::string address, uint16_t port, ProtocolType type,
                                   std::optional<std::string> ssl_name) {
        if(listeners.contains(name)) {
            throw "duplicate server!";
        }
        if(!addresses.contains(address)) {
            throw "address not found";
        }
        auto a = addresses[address];

        boost::asio::ssl::context *con = nullptr;

        if(ssl_name.has_value()) {
            if(!ssl_contexts.contains(ssl_name.value())) {
                throw "ssl context not found";
            }
            con = ssl_contexts[ssl_name.value()];
        }
        listeners[name] = new MudListener(*this, name, type, a, port, con);

    }

    void MudLink::registerAddress(std::string name, std::string addr) {
        addresses.emplace(name, boost::asio::ip::make_address(addr));
    }

    void MudLink::registerSSL(std::string name) {

    }

    void MudLink::startListening() {
        for(const auto & [k, v] : listeners) v->start();
    }

    void MudLink::stopListening() {
        for(const auto & [k, v] : listeners) v->stop();
    }
};