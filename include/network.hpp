// -----------------------------------------------------------------
// libdnsquery - a library to interrogate DNSs and more.
// Copyright (C) 2018-2023  Gabriele Bonacini
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

#pragma once

#include <sys/types.h>
#include <signal.h>

#include <cstdint>
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

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>


namespace networkutils{

    enum  NET_CONSTS          {  DNS_RESPONSE_SIZE     = 512,    
                                 DNS_BUFF_SIZE         = 548,
                                 DNS_PORT              = 53,
                                 DNS_TEST_PORT         = 33434,
                                 DNS_RESPONSE_TCP_SIZE = 40960,
                                 DNS_DEFAULT_TIMEOUT   = 6};

    using SockaddrIn          =  struct sockaddr_in;
    using Sockaddr            =  struct sockaddr;
    using ServerId            =  std::string;
    using Buffer              =  std::vector<uint8_t>;
    using Response            =  std::vector<uint8_t>;
    using Sigaction           =  struct sigaction;
    using TimePoint           =  std::chrono::time_point<std::chrono::system_clock>;
    using DurationTime        =  std::chrono::duration<double>;
    using Timeval             =  struct timeval;

    class Socket{
        public:
            virtual void        sendMsg(const Buffer& query, 
                                        Response& response)                   anyexcept = 0 ;

            virtual void        setTimeoutSecs(time_t tou)                    noexcept;
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
            Timeval                  timeout_sec;
            static std::atomic_bool  sigpipeOn;  
            std::string              wrnMsg;
            bool                     timeExc,
                                     signalExit;
            TimePoint                start,
                                     end;
            DurationTime             elapsed_seconds;
            fd_set                   sockSet;
            Sigaction                sigActionPipe;

            explicit           Socket(ServerId hst);
    };

    enum class SocketTypes    {  UdpSocket,         UdpSocketVerbose,  UdpSocketPing,
                                 UdpConnectedSocket,
                                 UdpSocketSp, 
                                 TcpSocket,         TcpSocketVerbose
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

    class SocketUdpConnected : public Socket{
        public:
            explicit SocketUdpConnected(ServerId hst);
            ~SocketUdpConnected(void)                                              override;

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

    using Msghdr=struct msghdr;
    using IcmpBuff=std::array<uint8_t, DNS_BUFF_SIZE>;

    using SockaddrStorage=struct sockaddr_storage;
    using Iovec=struct iovec;
    using Cmsghdr=struct cmsghdr;
    using Icmphdr=struct icmphdr;
    using SockExtendedErr=struct sock_extended_err;
   
    enum ICMP_ERR_CODES { ICMP_TYPE_DESTINATION_UNREACHABLE=3,
                          ICMP_CODE_PORT_UNREACHABLE=3,
                          ICMP_TYPE_TIME_EXCEEDED=11,
                          ICMP_CODE_TTL_EXCEEDED_IN_TRANSIT=0
    };

    class SocketUdpTraceroute : public SocketUdpConnected{
        public:
            explicit     SocketUdpTraceroute(ServerId hst);
            ~SocketUdpTraceroute(void)                                            override;

            void          sendMsg(const Buffer& query,
                                  Response& response)                             anyexcept override final;

            void          setTtl(int newTtl)                                      noexcept;
            void          setMaxTtl(uint8_t newMax)                               noexcept;
            void          setPort(uint16_t newPort)                               noexcept;
            void          setMaxPort(uint16_t newMaxPort)                         noexcept;
            virtual void  setTimeoutSecs(time_t tou)                              noexcept  override final;

        private:
            int                                  ttl,
                                                 icmpFd;
            uint8_t                              maxTtl;
            uint16_t                             port,
                                                 maxPort;
            IcmpBuff                             buffer;
            Sockaddr                             remoteAddr;
            Sigaction                            sigActionAlarm;
            time_t                               tout_sec;
            static std::atomic_bool              alarmOn; 

            void          applyTtl(void)                                          noexcept;
    }; 

    class SocketTcpVerbose : public SocketTcp {
        public:
            explicit SocketTcpVerbose(ServerId hst);

            void sendMsg(const Buffer& query,
                         Response& response)                             anyexcept override final;
    };

} // End Namespace

