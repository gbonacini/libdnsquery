// -----------------------------------------------------------------
// libdnsquery - a library to interrogate DNSs and more.
// Copyright (C) 2018  Gabriele Bonacini
//
// This program is free software for no profit use; you can redistribute 
// it and/or modify it under the terms of the GNU General Public License 
// as published by the Free Software Foundation; either version 2 of 
// the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software Foundation,
// Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
// A commercial license is also available for a lucrative use.
// -----------------------------------------------------------------

#ifndef  NETWORK_DNS_CLIENT_BG_HPP
#define  NETWORK_DNS_CLIENT_BG_HPP

#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <map>
#include <functional>
#include <memory>
#include <chrono>
#include <atomic>

#include <anyexcept.hpp>
#include <trace.hpp>

namespace networkutils{

    enum  NET_CONSTS          {  DNS_RESPONSE_SIZE     = 512,    DNS_PORT = 53,
                                 DNS_RESPONSE_TCP_SIZE = 40960 };

    using SockaddrIn          =  struct sockaddr_in;
    using Sockaddr            =  struct sockaddr;
    using ServerId            =  std::string;
    using Buffer              =  std::vector<uint8_t>;
    using Response            =  std::vector<uint8_t>;
    using Sigaction           =  struct sigaction;
    using TimePoint           =  std::chrono::time_point<std::chrono::system_clock>;
    using DurationTime        =  std::chrono::duration<double>;

    class Socket{
        public:
            virtual void        sendMsg(const Buffer& query, 
                                        Response& response)                   anyexcept = 0 ;

            void                setTimeoutSecs(time_t tou)                    noexcept;
            bool                isTimeout(void)                      const    noexcept;
            const std::string&  getWarningMsg(void)                  const    noexcept;
            double              getElapsedTime(void)                 const    noexcept;
            ssize_t             getRecvLen(void)                     const    noexcept;

            virtual             ~Socket(void);

        protected:
            int                      fd;
            ServerId                 serverid;
            socklen_t                len;
            ssize_t                  rcvResp;
            time_t                   timeout_sec;
            Sigaction                sigActionAlarm;
            static std::atomic_bool  alarmOn,
                                     sigpipeOn;
            std::string              wrnMsg;
            bool                     timeExc,
                                     signalExit;
            TimePoint                start,
                                     end;
            DurationTime             elapsed_seconds;

            explicit           Socket(ServerId hst);
    };

    enum class SocketTypes    {  UdpSocket,   UdpSocketVerbose,  UdpSocketPing,
                                 UdpSocketSp, 
                                 TcpSocket,   TcpSocketVerbose,
                              };

    using SocketCreatorFx     =  std::function<std::unique_ptr<Socket>(void)>;
    using CreatorsMap         =  std::map<SocketTypes, SocketCreatorFx>;

    class SocketCreator{
        public:
            static SocketCreator&    getInstance(ServerId   hst  = "",
                                        const std::string&  sp   = "",
                                        time_t              tout = 3)   anyexcept;
            std::unique_ptr<Socket>  createSocket(SocketTypes stype)    anyexcept;

        private:
            explicit SocketCreator(ServerId hst,   const std::string&  sp,
                                   time_t   tou);

            SocketCreator(SocketCreator const&)                         = delete;             
            SocketCreator(SocketCreator&&)                              = delete;                  
            SocketCreator& operator=(SocketCreator const&)              = delete; 
            SocketCreator& operator=(SocketCreator &&)                  = delete; 

            ServerId     servername;
            time_t       timeoutSecs;
            std::string  spoofing;
            CreatorsMap  creatorsMap;
    };

    class SocketUdp : public Socket{
        public:
            explicit SocketUdp(ServerId hst);
            ~SocketUdp(void)                                                       override;

            void sendMsg(const Buffer& query,
                         Response& response)                             anyexcept override;

            void setCloseOnError(bool)                                   noexcept;

        protected:
            SockaddrIn       sv;
            bool             closeOnError;
    };

    #ifdef OFFENSIVE_REL
    #include <networkraw.hpp>
    #endif

    class SocketTcp : public Socket {
        public:
            explicit SocketTcp(ServerId hst);
            ~SocketTcp(void)                                                       override;

            void sendMsg(const Buffer& query,
                         Response& response)                             anyexcept override;
        protected:
            SockaddrIn               sv;
            Response                 tcpBuffer;
    };

    class SocketUdpVerbose : public SocketUdp {
        public:
            explicit SocketUdpVerbose(ServerId hst);

            void sendMsg(const Buffer& query,
                         Response& response)                             anyexcept override final;
    };

    class SocketUdpPing : public SocketUdp{
        public:
            explicit SocketUdpPing(ServerId hst);

            void sendMsg(const Buffer& query,
                         Response& response)                             anyexcept override final;
    };

    class SocketTcpVerbose : public SocketTcp {
        public:
            explicit SocketTcpVerbose(ServerId hst);

            void sendMsg(const Buffer& query,
                         Response& response)                             anyexcept override final;
    };

} // End Namespace

#endif
