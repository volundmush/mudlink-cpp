//
// Created by volund on 11/27/20.
//

#include "mudlink/mudlink.hpp"
#include <iostream>

// MudConnection
MudConnection::MudConnection(MudListener& l, uint32_t id) : context(l.context), listener(l) {
    this->conn_id = id;
}

void MudConnection::onReady() {
    listener.link.connections[conn_id] = this;
    if(listener.link.onConnectCB) {
        listener.link.onConnectCB.value()(this);
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

bool MudConnection::isTLS() const {
    return listener.ssl_con != nullptr;
}

void MudConnection::onConnect() {
    if(isTLS()) {
        auto old = conn.peer;
        conn.secure_peer = new TlsSocket(std::move(*old), *listener.ssl_con);
        delete old;
        conn.secure_peer->async_handshake(boost::asio::ssl::stream_base::server, [&](std::error_code ec){
            if(!ec) {
                onSecureConnect();
            }});
    } else {
        onPlainConnect();
    }
}

// TelnetMudConnection
TelnetMudConnection::TelnetMudConnection(MudListener &l, uint32_t id) : MudConnection(l, id), timer(l.context) {
    hs_local = new TelnetHandshakeHolder(this);
    hs_remote = new TelnetHandshakeHolder(this);
    hs_special = new TelnetHandshakeHolder(this);
};

MudConnectionType TelnetMudConnection::getType() {
    return Telnet;
}

void TelnetMudConnection::onPlainConnect() {
    start();
}

void TelnetMudConnection::onSecureConnect() {
    start();
}


void TelnetMudConnection::registerOption(TelnetOption *op) {
    options[op->opCode()] = op;
    op->registerHandshake();
}

void TelnetMudConnection::start() {
    // register options.
    //registerOption(new MXPOption(this));

    // Start up the async networking I/O.
    send();
    receive();

    // Start all option handlers.
    for(const auto & [k, v] : options) {
        v->onConnect();
    }

    // start timer - this handles a case where the client doesn't do telnet negotiation
    // or doesn't answer all of our handshakes.
    timer.expires_after(std::chrono::milliseconds(500));
    timer.async_wait([&](std::error_code ec) {
        finishReady();
    });
}

void TelnetMudConnection::checkReady() {
    if(started) {
        return;
    }
    if(!hs_local->empty()) {
        return;
    }
    if(!hs_remote->empty()) {
        return;
    }
    if(!hs_special->empty()) {
        return;
    }
    finishReady();
}

void TelnetMudConnection::finishReady() {
    if(started) {
        return;
    }
    started = true;
    onReady();
}

void TelnetMudConnection::send() {

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

void TelnetMudConnection::sendNegotiate(TelnetCode command, TelnetCode option) {
    auto a = outbox.prepare(3);
    uint8_t c[3] = {TelnetCode::IAC, command, option};
    memcpy(a.data(), &c, 3);
    outbox.commit(3);
    send();
};


void TelnetMudConnection::receive() {
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

void TelnetMudConnection::onReceive() {
    while(inbox.size() > 0) {
        auto box = inbox.data();
        auto available = inbox.size();
        auto begin = boost::asio::buffers_begin(box), end = boost::asio::buffers_end(box);
        // first, we read ahead
        if((uint8_t)*begin == (uint8_t)TelnetCode::IAC) {
            if(available < 2) {
                // not enough bytes available - do nothing;
                return;
            } else {
                // we have 2 or more bytes!
                auto b = begin;
                b++;
                if((uint8_t)*b == (uint8_t)TelnetCode::IAC) {
                    // this is an escaped IAC.
                    auto t = new TelnetMessage;
                    t->msg_type = TelnetMsgType::AppData;
                    t->data.push_back(TelnetCode::IAC);
                    onReceiveMessage(t);
                    inbox.consume(2);
                    continue;
                } else {
                    // It's not an escaped IAC...
                    if(((uint8_t)*b == (uint8_t)TelnetCode::WILL) ||
                       ((uint8_t)*b == (uint8_t)TelnetCode::WONT) ||
                       ((uint8_t)*b == (uint8_t)TelnetCode::DO) ||
                       ((uint8_t)*b == (uint8_t)TelnetCode::DONT)) {
                        if(inbox.size() > 2) {
                            // IAC negotiation received.
                            auto t = new TelnetMessage;
                            t->msg_type = TelnetMsgType::Negotiation;
                            t->codes[0] = (uint8_t)*b;
                            t->codes[1] = (uint8_t)*(++b);
                            onReceiveMessage(t);
                            inbox.consume(3);
                            continue;
                        } else {
                            // It's negotiation, but we need more data.
                            return;
                        }
                    } else {
                        // It's not a negotiation, so it's either a subnegotiation or a command.
                        if((uint8_t)*b == (uint8_t)TelnetCode::SB) {
                            // This is a subnegotiation. we will require at least 5 bytes for this to be usable.
                            if(inbox.size() >= 5) {
                                uint8_t option = *(++b);
                                auto sub = ++b;
                                // we must seek ahead until we have an unescaped IAC SE. If we don't have one, do nothing.
                                bool escaped = false, match1 = false, match2 = false;
                                while(b != end) {
                                    switch((uint8_t)*b) {
                                        case TelnetCode::IAC:
                                            if(match1) {
                                                escaped = true;
                                                match1 = false;
                                            } else {
                                                match1 = true;
                                            }
                                            break;
                                        case TelnetCode::SE:
                                            if(match1) {
                                                match2 = true;
                                            }
                                            // we have a winner!;
                                            b--;
                                            auto t = new TelnetMessage;
                                            t->msg_type = TelnetMsgType::Subnegotiation;
                                            t->codes[0] = option;
                                            t->data = std::string(sub, b);
                                            inbox.consume(5 + t->data.size());
                                            onReceiveMessage(t);
                                    }
                                }
                            } else {
                                // Not enough data. wait for more.
                                return;
                            }
                        } else {
                            // Yeah, it's a command...
                            auto t = new TelnetMessage;
                            t->msg_type = TelnetMsgType::Command;
                            t->codes[0] = (uint8_t)*b;
                            onReceiveMessage(t);
                            inbox.consume(2);
                            continue;
                        }
                    }
                }
            }
        } else {
            // Data begins on something that isn't an IAC. Scan ahead until we reach one...
            // Send all data up to an IAC, or everything if there is no IAC, as data.

            auto t = new TelnetMessage;
            t->msg_type = TelnetMsgType::AppData;
            auto check = std::find(begin, end, TelnetCode::IAC);
            t->data = std::string(begin, check);
            inbox.consume(t->data.size());
            onReceiveMessage(t);
            continue;
        }
    }
}

void TelnetMudConnection::onReceiveAppData(TelnetMessage *msg) {
    // First, copy msg data to cmdbuff.
    cmdbuff.append(msg->data);

    // Keep scanning cmdbuff for commands delimited by LF.
    while(cmdbuff.size() > 0) {
        auto begin = cmdbuff.begin();
        auto end = cmdbuff.end();
        auto check = std::find(begin, end, TelnetCode::LF);
        // if there is no LF, we break the while loop. Perhaps next time this
        // is called, we'll have an LF.
        if(check == end) {
            break;
        }
        // increment iterator to contain the LF.
        check++;

        // Copy the command and trim whitespace.
        std::string cmd(begin, check);
        boost::algorithm::trim(cmd);

        // remove the command from cmdbuff.
        cmdbuff = std::string(check, end);

        // fire callback to alert program that this command arrived.
        if(onCommandCB) {
            onCommandCB.value()(cmd);
        }
    }
}

void TelnetMudConnection::onReceiveNegotiation(TelnetMessage *msg) {
    auto cmd = msg->codes[0];
    auto opcode = msg->codes[1];
    if(options.contains((uint8_t)opcode)) {
        options[(uint8_t)opcode]->negotiate((TelnetCode)cmd);
    } else {
        // we received a negotiaton for something we don't support at all.
        switch(cmd) {
            case TelnetCode::WILL:
                sendNegotiate(TelnetCode::DONT, (TelnetCode)opcode);
                break;
            case TelnetCode::DO:
                sendNegotiate(TelnetCode::WONT, (TelnetCode)opcode);
                break;
                // Receiving WONT or DONT unprompted is not part of telnet RFC.
                // just ignore it.
            case TelnetCode::WONT:
                break;
            case TelnetCode::DONT:
                break;
        }
    }
}

void TelnetMudConnection::onReceiveSubnegotiation(TelnetMessage *msg) {
    auto code = msg->codes[0];
    if(options.contains((uint8_t)code)) {
        std::string data(msg->data.begin(), msg->data.end());
        options[(uint8_t)code]->receiveSubnegotiate(data);
    }
    // else, just ignore it.
}

void TelnetMudConnection::onReceiveCommand(TelnetMessage *msg) {

}

void TelnetMudConnection::onReceiveMessage(TelnetMessage *msg) {
    switch(msg->msg_type) {
        case AppData:
            onReceiveAppData(msg);
            break;
        case Command:
            onReceiveCommand(msg);
            break;
        case Negotiation:
            onReceiveNegotiation(msg);
            break;
        case Subnegotiation:
            onReceiveSubnegotiation(msg);
            break;
    }
    delete msg;
}

// TelnetHandshakeHolder
TelnetHandshakeHolder::TelnetHandshakeHolder(TelnetMudConnection* connection) {
    conn = connection;
}

void TelnetHandshakeHolder::registerHandshake(TelnetCode code) {
    handshakes.insert(code);
}

void TelnetHandshakeHolder::processHandshake(TelnetCode code) {
    handshakes.erase(code);
    if(empty()) {
        conn->checkReady();
    }
}

bool TelnetHandshakeHolder::empty() {return handshakes.empty();}


// TelnetOptions
TelnetOption::TelnetOption(TelnetMudConnection *connection) {
    conn = connection;
}

void TelnetOption::registerHandshake() {
    if(supportLocal() && startDo()) {
        conn->hs_local->registerHandshake(opCode());
    }
    if(supportRemote() && startWill()) {
        conn->hs_remote->registerHandshake(opCode());
    }
}

bool TelnetOption::startWill() {return false;}
bool TelnetOption::startDo() {return false;}
bool TelnetOption::supportLocal() {return false;}
bool TelnetOption::supportRemote() {return false;}

void TelnetOption::negotiate(TelnetCode command) {
    switch(command) {
        case TelnetCode::DO:
            remote.negotiating = true;
            conn->sendNegotiate(command, opCode());
            break;
        case TelnetCode::WILL:
            local.negotiating = true;
            conn->sendNegotiate(command, opCode());
            break;
        default:
            break;
    }
}

void TelnetOption::onConnect() {
    if(startWill()) {
        negotiate(TelnetCode::WILL);
    }
    if(startDo()) {
        negotiate(TelnetCode::DO);
    }
}

void TelnetOption::receiveNegotiate(TelnetCode command) {
    switch(command) {
        case TelnetCode::WILL:
            if(supportRemote()) {
                if(remote.negotiating) {
                    remote.negotiating = false;
                    if(!remote.enabled) {
                        remote.enabled = true;
                        enableRemote();
                        if(!remote.answered) {
                            remote.answered = true;
                            conn->hs_remote->processHandshake(opCode());
                        }
                    }
                } else {
                    remote.enabled = true;
                    conn->sendNegotiate(TelnetCode::DO, opCode());
                    enableRemote();
                    if(!remote.answered) {
                        remote.answered = true;
                        conn->hs_remote->processHandshake(opCode());
                    }
                }
            } else {
                conn->sendNegotiate(TelnetCode::DONT, opCode());
            }
            break;
        case TelnetCode::DO:
            if(supportLocal()) {
                if(local.negotiating) {
                    local.negotiating = false;
                    if(!local.enabled) {
                        local.enabled = true;
                        enableLocal();
                        if(!local.answered) {
                            local.answered = true;
                            conn->hs_local->processHandshake(opCode());
                        }
                    }
                } else {
                    local.enabled = true;
                    conn->sendNegotiate(TelnetCode::WILL, opCode());
                    enableLocal();
                    if(!local.answered) {
                        local.answered = true;
                        conn->hs_local->processHandshake(opCode());
                    }
                }
            } else {
                conn->sendNegotiate(TelnetCode::WONT, opCode());
            }
            break;
        case TelnetCode::WONT:
            if(remote.enabled) disableRemote();
            if(remote.negotiating) {
                remote.negotiating = false;
                if(!remote.answered) {
                    remote.answered = true;
                    conn->hs_remote->processHandshake(opCode());
                }
            }
            break;
        case TelnetCode::DONT:
            if(local.enabled) disableLocal();
            if(local.negotiating) {
                local.negotiating = false;
                if(!local.answered) {
                    local.answered = true;
                    conn->hs_local->processHandshake(opCode());
                }
            }
            break;
        default:
            break;
    }
}

void TelnetOption::enableLocal() {}
void TelnetOption::enableRemote() {}
void TelnetOption::disableLocal() {}
void TelnetOption::disableRemote() {}
void TelnetOption::rejectLocalHandshake() {}
void TelnetOption::rejectRemoteHandshake() {}
void TelnetOption::acceptLocalHandshake() {}
void TelnetOption::acceptRemoteHandshake() {}

void TelnetOption::receiveSubnegotiate(std::string &data) {

}

// Option - MXP
MXPOption::MXPOption(TelnetMudConnection *connection) : TelnetOption(connection) {};
TelnetCode MXPOption::opCode() {return TelnetCode::MXP;}



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



MudListener::MudListener(MudLink& link, std::string& name, MudConnectionType type, boost::asio::ip::address& addr, uint16_t port,
                   boost::asio::ssl::context* ssl_context)
    : link(link), address(addr), context(link.context),
    acceptor(link.context, boost::asio::ip::tcp::endpoint(address, port)) {
    this->name = name;
    this->type = type;
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
            switch(type) {
                case Telnet:
                    mud = new TelnetMudConnection(*this, link.nextId++);
                    break;
                case WebSocket:
                    mud = new WebSocketMudConnection(*this, link.nextId++);
                    break;
            }
            mud->address = sock.local_endpoint().address();
            mud->conn.peer = new TcpSocket(std::move(sock));
            link.pending[mud->conn_id] = mud;
            mud->onConnect();
        }
        if(running) {
            listen();
        }
    });
}


MudLink::MudLink(boost::asio::io_context& io_con)
    : context(io_con) {
}

void MudLink::registerListener(std::string name, std::string address, uint16_t port, MudConnectionType type,
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