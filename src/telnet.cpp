//
// Created by volund on 5/9/21.
//

#include "mudlink/telnet.hpp"

namespace mudlink::telnet {

    bool TelnetHandshakeHolder::empty() const {
        return local.empty() && remote.empty() && special.empty();
    }

    TelnetMessage::TelnetMessage(MessageType mt) {
        mtype = mt;
    }

    std::optional<TelnetMessage> TelnetMessage::parse_bytes(boost::asio::streambuf &buf) {
        auto box = buf.data();
        auto available = buf.size();
        std::optional<TelnetMessage> out;
        if(available == 0) {
            return out;
        }

        auto begin = boost::asio::buffers_begin(box), end = boost::asio::buffers_end(box);
        // first, we read ahead
        if((uint8_t)*begin == (uint8_t)TelnetCode::IAC) {
            if(available < 2) {
                // not enough bytes available - do nothing;
                return out;
            } else {
                // we have 2 or more bytes!
                auto b = begin;
                b++;
                if((uint8_t)*b == (uint8_t)TelnetCode::IAC) {
                    // this is an escaped IAC.
                    out.emplace(MessageType::Data);
                    out.value().data.push_back(TelnetCode::IAC);
                    buf.consume(2);
                    return out;
                } else {
                    // It's not an escaped IAC...
                    if(((uint8_t)*b == (uint8_t)TelnetCode::WILL) ||
                       ((uint8_t)*b == (uint8_t)TelnetCode::WONT) ||
                       ((uint8_t)*b == (uint8_t)TelnetCode::DO) ||
                       ((uint8_t)*b == (uint8_t)TelnetCode::DONT)) {
                        if(buf.size() > 2) {
                            // IAC negotiation received.
                            out.emplace(MessageType::Negotiation);
                            out.value().option = (uint8_t)*b;
                            out.value().extra = (uint8_t)*(++b);
                            buf.consume(3);
                            return out;
                        } else {
                            // It's negotiation, but we need more data.
                            return out;
                        }
                    } else {
                        // It's not a negotiation, so it's either a subnegotiation or a command.
                        if((uint8_t)*b == (uint8_t)TelnetCode::SB) {
                            // This is a subnegotiation. we will require at least 5 bytes for this to be usable.
                            if(buf.size() >= 5) {
                                uint8_t op = *(++b);
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
                                            out.emplace(MessageType::SubNegotiation);
                                            out.value().option = op;
                                            out.value().data.append(sub, b);
                                            buf.consume(5 + out.value().data.size());
                                            return out;
                                    }
                                }
                            } else {
                                // Not enough data. wait for more.
                                return out;
                            }
                        } else {
                            // Yeah, it's a command...
                            out.emplace(MessageType::Command);
                            out.value().option = (uint8_t)*b;
                            buf.consume(2);
                            return out;
                        }
                    }
                }
            }
        } else {
            // Data begins on something that isn't an IAC. Scan ahead until we reach one...
            // Send all data up to an IAC, or everything if there is no IAC, as data.
            out.emplace(MessageType::Data);
            auto check = std::find(begin, end, TelnetCode::IAC);
            out.value().data.append(begin, check);
            buf.consume(out.value().data.size());
            return out;
        }
        return out;
    }

    TelnetConnection::TelnetConnection(ConnQueue &cq, uint32_t id) : MudConnection(cq, id), timer(cq.io_con) {

    }

    void TelnetConnection::sendBytes(std::string &data) {
        auto a = outbox.prepare(data.size());
        memcpy(a.data(), data.c_str(), data.size());
        outbox.commit(data.size());
        send();
    }
    
    void TelnetConnection::start() {
        std::string data;
        
        for(auto c: supported) {
            states.emplace(std::pair<uint8_t, TelnetOpState>(c, TelnetOpState{}));
        }
        
        for(auto c : start_local) {
            data.push_back(IAC);
            data.push_back(WILL);
            data.push_back(c);
            states[c].local.negotiating = true;
            handshakes.local.insert(c);
        }
        
        for(auto c: start_remote) {
            data.push_back(IAC);
            data.push_back(DO);
            data.push_back(c);
            states[c].remote.negotiating = true;
            handshakes.remote.insert(c);
        }
        
        sendBytes(data);
        timer.expires_after(std::chrono::milliseconds(500));
        timer.async_wait([&](std::error_code ec) {
            finishReady();
        });
    }

    void TelnetConnection::finishReady() {
        if(active) return;
        active = true;
        if(!pending_events.empty()) {
            in_mut.lock();
            for(const auto& e : pending_events) {
                in_events.push_back(e);
            }
            in_mut.unlock();
            pending_events.clear();
            pending_events.shrink_to_fit();
        }

        MsgToMud m{ToMudEvent::Ready, 0};
        sendToMud(m);
    }
    
    void TelnetConnection::sendSubNegotiate(TelnetCode op, std::string &data) {
        std::string out;

        out.push_back(IAC);
        out.push_back(SB);
        out.push_back(op);
        out.append(data);
        out.push_back(IAC);
        out.push_back(SE);
        
        sendBytes(out);
    }

    void TelnetConnection::onReceive() {
        while(true) {
            auto m = TelnetMessage::parse_bytes(inbox);
            if(m) {
                processMessage(m.value());
            } else {
                break;
            }
        }
    }

    void TelnetConnection::receiveData(std::string &data) {
        // First, copy msg data to cmdbuff.
        cmdbuff.append(data);

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

            MsgToMud m{ToMudEvent::Ready, cmd};
            sendToMud(m);
        }
    }

    void TelnetConnection::receiveCommand(uint8_t cmd) {

    }

    void TelnetConnection::processFromMud(MsgFromMud &ev) {

    }

    void TelnetConnection::processMessage(TelnetMessage &msg) {
        switch(msg.mtype) {
            case MessageType::Data:
                receiveData(msg.data);
                break;
            case MessageType::Command:
                receiveCommand(msg.option);
                break;
            case MessageType::SubNegotiation:
                receiveSubnegotiation(msg.option, msg.data);
                break;
            case MessageType::Negotiation:
                receiveNegotiate(static_cast<TelnetCode>(msg.option), msg.extra);
                break;
            default:
                break;
        }

        if(active) {
            if(changed) {
                changed = false;
                MsgToMud m{ToMudEvent::Update, 0};
                sendToMud(m);
            }
        } else {
            if(handshakes.empty()) finishReady();
        }
    }



    void TelnetConnection::sendNegotiation(TelnetCode neg, uint8_t op) {
        std::string out;
        out.push_back(IAC);
        out.push_back(neg);
        out.push_back(op);
        sendBytes(out);
    }

    void TelnetConnection::receiveSubnegotiation(uint8_t op, std::string &data) {
        if(supportAny(op)) {
            auto code = (TelnetCode)op;
            switch(code) {
                default:
                    break;
            }
        }
    }

    bool TelnetConnection::supportAny(uint8_t code) {
        return std::find(std::begin(supported), std::end(supported), code) != std::end(supported);
    }

    bool TelnetConnection::supportLocal(uint8_t code) {
        return std::find(std::begin(support_local), std::end(support_local), code) != std::end(support_local);
    }

    bool TelnetConnection::supportRemote(uint8_t code) {
        return std::find(std::begin(support_remote), std::end(support_remote), code) != std::end(support_remote);
    }

    void TelnetConnection::receiveNegotiate(TelnetCode command, uint8_t op) {
        if(supportAny(op)) {
            auto code = (TelnetCode)op;
            auto state = states[code];
            switch(command) {
                case TelnetCode::WILL:
                    if(supportRemote(code)) {

                        if(state.remote.negotiating) {
                            state.remote.negotiating = false;
                            if(!state.remote.enabled) {
                                state.remote.enabled = true;
                                enableRemote(code);
                                if(!state.remote.answered) {
                                    state.remote.answered = true;
                                    handshakes.remote.erase(code);
                                }
                            }
                        } else {
                            state.remote.enabled = true;
                            sendNegotiation(TelnetCode::DO, code);
                            enableRemote(code);
                            if(!state.remote.answered) {
                                state.remote.answered = true;
                                handshakes.remote.erase(code);
                            }
                        }
                    } else {
                        sendNegotiation(TelnetCode::DONT, code);
                    }
                    break;
                case TelnetCode::DO:
                    if(supportLocal(code)) {
                        if(state.local.negotiating) {
                            state.local.negotiating = false;
                            if(!state.local.enabled) {
                                state.local.enabled = true;
                                enableLocal(code);
                                if(!state.local.answered) {
                                    state.local.answered = true;
                                    handshakes.local.erase(code);
                                }
                            }
                        } else {
                            state.local.enabled = true;
                            sendNegotiation(TelnetCode::WILL, code);
                            enableLocal(code);
                            if(!state.local.answered) {
                                state.local.answered = true;
                                handshakes.local.erase(code);
                            }
                        }
                    } else {
                        sendNegotiation(TelnetCode::WONT, code);
                    }
                    break;
                case TelnetCode::WONT:
                    if(state.remote.enabled) disableRemote(code);
                    if(state.remote.negotiating) {
                        state.remote.negotiating = false;
                        if(!state.remote.answered) {
                            state.remote.answered = true;
                            handshakes.remote.erase(code);
                        }
                    }
                    break;
                case TelnetCode::DONT:
                    if(state.local.enabled) disableLocal(code);
                    if(state.local.negotiating) {
                        state.local.negotiating = false;
                        if(!state.local.answered) {
                            state.local.answered = true;
                            handshakes.local.erase(code);
                        }
                    }
                    break;
                default:
                    break;
            }

        }
    }
    
    void TelnetConnection::enableLocal(TelnetCode op) {
        
    }

    void TelnetConnection::enableRemote(TelnetCode op) {

    }

    void TelnetConnection::disableLocal(TelnetCode op) {

    }

    void TelnetConnection::disableRemote(TelnetCode op) {

    }
    
}