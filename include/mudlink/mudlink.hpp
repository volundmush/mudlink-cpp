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

#include "mudlink/mudconn.hpp"
#include "mudlink/telnet.hpp"




namespace mudlink {

    class MudLink;
    class MudListener;

    class MudListener {
    public:
        MudListener(MudLink& lnk, std::string& name, ProtocolType type, boost::asio::ip::address& addr, uint16_t port,
                    boost::asio::ssl::context* ssl_context);

        void listen();
        void start();
        void stop();
        MudLink& link;
        ProtocolType ptype;
        ConnQueue &cqueue;
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
        MudLink(ConnQueue &cq);
        void registerSSL(std::string name);
        void registerAddress(std::string name, std::string addr);
        void registerListener(std::string name, std::string address, uint16_t port, ProtocolType type,
                              std::optional<std::string> ssl_name);
        void startListening();
        void stopListening();
        std::unordered_map<std::string, MudListener*> listeners;
        uint32_t nextId = 0;
        std::unordered_map<std::string, boost::asio::ip::address> addresses;
        std::unordered_map<std::string, boost::asio::ssl::context*> ssl_contexts;
        ConnQueue &cqueue;
    };

}


#endif //MUDLINK_MUDLINK_H
