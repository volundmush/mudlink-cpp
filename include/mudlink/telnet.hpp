//
// Created by volund on 5/9/21.
//

#ifndef MUDLINK_TELNET_H
#define MUDLINK_TELNET_H

#include <vector>
#include <memory>
#include <cstdint>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <boost/asio/streambuf.hpp>
#include <boost/asio/buffers_iterator.hpp>
#include <boost/algorithm/string/trim.hpp>
#include "mudlink/mudconn.hpp"

namespace mudlink::telnet {

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
        MTTS = 24

    };

    enum MessageType {
        Data = 0,
        Negotiation = 1,
        SubNegotiation = 2,
        Command = 3
    };

    struct TelnetMessage {
        MessageType mtype;
        uint8_t option, extra;
        std::string data;
        explicit TelnetMessage(MessageType mt);
        static std::optional<TelnetMessage> parse_bytes(boost::asio::streambuf &buf);
    };

    struct TelnetOptionPerspective {
        bool enabled = false, negotiating = false, answered = false;
    };

    struct TelnetOpState {
        TelnetOptionPerspective local, remote;
    };

    struct TelnetHandshakeHolder {
        std::unordered_set<TelnetCode> local, remote, special;
        bool empty() const;
    };

    struct TelnetConnection : public MudConnection {
        explicit TelnetConnection(ConnQueue &cq, uint32_t id);
        constexpr static TelnetCode supported[] = {SGA, NAWS, MTTS, MXP, MSSP, MCCP2, MCCP3, GMCP, MSDP, LINEMODE, TELOPT_EOR};
        constexpr static TelnetCode start_local[] = {SGA, MSSP, GMCP, MSDP, TELOPT_EOR};
        constexpr static TelnetCode support_local[] = {SGA, MSSP, GMCP, MSDP, TELOPT_EOR};
        constexpr static TelnetCode start_remote[] = {NAWS, MTTS, LINEMODE};
        constexpr static TelnetCode support_remote[] = {SGA, NAWS, MTTS, MSSP, GMCP, MSDP, LINEMODE, TELOPT_EOR};
        std::unordered_map<uint8_t, TelnetOpState> states;
        std::string cmdbuff;
        std::optional<std::string> mtts_last;
        TelnetHandshakeHolder handshakes;
        bool sga = true, compress, changed = false;
        boost::asio::high_resolution_timer timer;
        static bool supportRemote(uint8_t code), supportLocal(uint8_t code), supportAny(uint8_t code);
        void sendBytes(std::string &data);
        void start() override;
        void onReceive() override;
        void processFromMud(MsgFromMud &ev) override;
        void finishReady();
        void receiveData(std::string &data);
        void receiveCommand(uint8_t cmd);
        void sendSubNegotiate(TelnetCode op, std::string &data);
        void receiveNegotiate(TelnetCode neg, uint8_t op);
        void sendNegotiation(TelnetCode neg, uint8_t op);
        void receiveSubnegotiation(uint8_t op, std::string &data);
        void processMessage(TelnetMessage &msg);
        void enableLocal(TelnetCode op);
        void enableRemote(TelnetCode op);
        void disableLocal(TelnetCode op);
        void disableRemote(TelnetCode op);
    };

}

#endif //MUDLINK_TELNET_H
