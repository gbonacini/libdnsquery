#include <network.hpp>

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstdio>
#include <cstring>

#include <safeconversion.hpp>

namespace networkutils{

    using std::cerr;
    using std::endl;
    using std::string;
    using std::to_string;
    using std::unique_ptr;
    using std::make_pair;
    using std::make_unique;
    using std::atomic_bool;
    using std::chrono::system_clock;

    using stringutils::trace;

    SocketCreator& SocketCreator::getInstance(ServerId hst, const string& sp, time_t tout) anyexcept{
            #if defined __clang_major__ &&  __clang_major__ >= 4 
            #pragma clang diagnostic push 
            #pragma clang diagnostic ignored "-Wexit-time-destructors"
            #endif

           static SocketCreator instance(hst, sp, tout);

           #ifdef __clang__
           #pragma clang diagnostic pop
           #endif

           return instance;
    }

    unique_ptr<Socket>  SocketCreator::createSocket(SocketTypes stype) anyexcept {
         try{
            return creatorsMap[stype]();
         }catch(string& err){
             throw string("SocketCreator::createSocket: error : ").append(err);
         }catch(...){
             throw string("SocketCreator::createSocket: unexpected error creating socket.");
         }
    }

    SocketCreator::SocketCreator(ServerId hst, const string& sp, time_t tou)
        :  servername{hst},
           timeoutSecs{tou},
           spoofing{sp},
           creatorsMap {  make_pair(SocketTypes::UdpSocket,          
                                    [&]() -> unique_ptr<Socket>{ auto sckt { make_unique<SocketUdp>(servername) }; 
                                                                 sckt->setTimeoutSecs(timeoutSecs);
                                                                 return sckt; }),
                          #ifdef OFFENSIVE_REL
                          make_pair(SocketTypes::UdpSocketSp,          
                                    [&]() -> unique_ptr<Socket>{ auto sckt { make_unique<SocketRawUdp>(servername, spoofing) }; 
                                                                 sckt->setTimeoutSecs(timeoutSecs);
                                                                 return sckt; }),
                          #endif
                          make_pair(SocketTypes::UdpSocketVerbose,   
                                    [&]() -> unique_ptr<Socket>{ auto sckt { make_unique<SocketUdpVerbose>(servername) }; 
                                                                 sckt->setTimeoutSecs(timeoutSecs);
                                                                 return sckt; }),
                          make_pair(SocketTypes::UdpSocketPing,   
                                    [&]() -> unique_ptr<Socket>{ auto sckt { make_unique<SocketUdpPing>(servername) }; 
                                                                 sckt->setTimeoutSecs(timeoutSecs);
                                                                 return sckt; }),
                          make_pair(SocketTypes::TcpSocket,          
                                    [&]() -> unique_ptr<Socket>{ auto sckt {  make_unique<SocketTcp>(servername) }; 
                                                                 sckt->setTimeoutSecs(timeoutSecs);
                                                                 return sckt; }),
                          make_pair(SocketTypes::TcpSocketVerbose,   
                                    [&]() -> unique_ptr<Socket>{ auto sckt {  make_unique<SocketTcpVerbose>(servername) }; 
                                                                 sckt->setTimeoutSecs(timeoutSecs);
                                                                 return sckt; }),
                          make_pair(SocketTypes::UdpConnectedSocket,   
                                    [&]() -> unique_ptr<Socket>{ auto sckt {  make_unique<SocketUdpConnected>(servername) }; 
                                                                 sckt->setTimeoutSecs(timeoutSecs);
                                                                 return sckt; })
                       }
    {}

    atomic_bool Socket::alarmOn{false};
    atomic_bool Socket::sigpipeOn{false};

    Socket::Socket(ServerId hst)
         : fd{-1}, serverid{hst}, len{0}, rcvResp{0}, timeout_sec{}, wrnMsg{""}, 
           timeExc{false}, signalExit{false}
    {
        Socket::alarmOn              =  false;
        Socket::sigpipeOn            =  false;
        sigemptyset(&sigActionAlarm.sa_mask);
        sigActionAlarm.sa_flags      =  0;
        sigActionAlarm.sa_handler    =  [](int){ Socket::alarmOn   = true; };
        if(sigaction(SIGALRM, &sigActionAlarm, nullptr) != 0)
             throw string("SocketTcp: setting alarm hdlr.").append(strerror(errno));
        sigActionAlarm.sa_handler    =  [](int){ Socket::sigpipeOn = true; };
        if(sigaction(SIGPIPE, &sigActionAlarm, nullptr) != 0)
             throw string("SocketTcp: setting sigpipe hdlr.").append(strerror(errno));
    }

    Socket::~Socket(void){
        sigemptyset(&sigActionAlarm.sa_mask);
        sigActionAlarm.sa_flags          = 0;
        sigActionAlarm.sa_flags          = sigActionAlarm.sa_flags | SA_RESETHAND;
        sigActionAlarm.sa_handler        = nullptr;

        static_cast<void>(sigaction(SIGALRM, &sigActionAlarm, nullptr));
    }

    ssize_t Socket::getRecvLen(void)  const noexcept{
        return rcvResp;
    }

    const string&  Socket::getWarningMsg(void) const noexcept{
        return wrnMsg; 
    }

    double  Socket::getElapsedTime(void) const noexcept{
        return elapsed_seconds.count();
    }

    bool Socket::isTimeout(void) const noexcept{
        return timeExc;
    }

    void  Socket::setTimeoutSecs(time_t tou)  noexcept{
        timeout_sec  =  tou;
    }

    #ifdef OFFENSIVE_REL
    #include "networkraw.cpp"
    #endif

    SocketUdp::SocketUdp(ServerId hst)
         : Socket{hst}, sv{}, closeOnError{true}
    {
        sv.sin_family       = AF_INET;
        sv.sin_port         = htons(DNS_PORT); 
        sv.sin_addr.s_addr  = inet_addr(serverid.c_str());

        fd    =  socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(fd == -1)  
            throw string("SocketUdp: can't create socket.").append(strerror(errno));

        int reuse { 1 };
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0)
            throw string("SocketUdp: can't configure socket SO_REUSEADDR.").append(strerror(errno));
    }

    void SocketUdp::setCloseOnError(bool onOff) noexcept{
          closeOnError  = onOff;
    }

    SocketUdp::~SocketUdp(void){
        if(fd != -1)     
            close(fd);
    }

    void SocketUdp::sendMsg(const Buffer& query, Response& response) anyexcept {
        alarm(static_cast<unsigned int>(timeout_sec));
        ssize_t   ret   {  ::sendto(fd, query.data(),                           query.size(), 
                                    0,  reinterpret_cast<const Sockaddr*>(&sv), sizeof(sv)) };
        alarm(0);
        if(ret == -1 ){ 
            if(closeOnError){ 
	            close(fd); 
                fd  =  -1;
            }

            if(alarmOn)
                throw string("Timeout.");

            throw string("SocketUdp::sendMsg: can't send the query: ").append(strerror(errno));
        }

        alarm(static_cast<unsigned int>(timeout_sec));
	    rcvResp     =  ::recvfrom(fd, response.data(), response.size(), 0, reinterpret_cast< Sockaddr*>(&sv), &len);
        alarm(0);
        if(rcvResp == -1){ 
            if(closeOnError){ 
                if(Socket::alarmOn){
                    wrnMsg   =  "SocketUdp::sendMsg: time exceed."; 
                    timeExc  =  true;
                }else{
	               close(fd);  
                   fd  =  -1;
                }
            }

            if(alarmOn)
                throw string("Timeout.");

            throw string("SocketUdp::sendMsg: can't read query response: ").append(strerror(errno));
        }
        
    }

    SocketUdpConnected::SocketUdpConnected(ServerId hst)
         : Socket{hst}, sv{}, closeOnError{true}
    {
        sv.sin_family       = AF_INET;
        sv.sin_port         = htons(DNS_PORT); 
        sv.sin_addr.s_addr  = inet_addr(serverid.c_str());

        fd    =  socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(fd == -1)  
            throw string("SocketUdpConnected: can't create socket.").append(strerror(errno));

        if(connect(fd, reinterpret_cast<Sockaddr*>(&sv), sizeof(sv)) < 0) 
            throw string("\n Error : UDP Socket Connect Failed \n"); 


        int reuse { 1 };
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0)
            throw string("SocketUdpConnected: can't configure socket SO_REUSEADDR.").append(strerror(errno));
    }

    void SocketUdpConnected::setCloseOnError(bool onOff) noexcept{
          closeOnError  = onOff;
    }

    SocketUdpConnected::~SocketUdpConnected(void){
        if(fd != -1)     
            close(fd);
    }

    void SocketUdpConnected::sendMsg(const Buffer& query, Response& response) anyexcept {
        alarm(static_cast<unsigned int>(timeout_sec));
        ssize_t   ret   {  ::send(fd, query.data(), query.size(), 0) };                            
        alarm(0);
        if(ret == -1 ){ 
            if(closeOnError){ 
	            close(fd); 
                fd  =  -1;
            }

            if(alarmOn)
                throw string("Timeout.");
            throw string("SocketUdpConnected::sendMsg: can't send the query: ").append(strerror(errno));
        }

        alarm(static_cast<unsigned int>(timeout_sec));
        rcvResp     =  ::recv(fd, response.data(), response.size(), 0); 
        alarm(0);
        if(rcvResp == -1){ 
            if(closeOnError){ 
                if(Socket::alarmOn){
                    wrnMsg   =  "SocketUdpConnected::sendMsg: time exceed."; 
                    timeExc  =  true;
                }else{
	               close(fd);  
                   fd  =  -1;
                }
            }

            if(alarmOn)
                throw string("Timeout.");
            throw string("SocketUdpConnected::sendMsg: can't read query response: ").append(strerror(errno));
        }
    }

    SocketTcp::SocketTcp(ServerId hst)
         : Socket{hst}, sv{},
           tcpBuffer(DNS_RESPONSE_TCP_SIZE, 0)
    {
        sv.sin_family       = AF_INET;
        sv.sin_port         = htons(DNS_PORT); 
        sv.sin_addr.s_addr  = inet_addr(serverid.c_str());

        fd    =  socket(AF_INET, SOCK_STREAM, 0);
        if(fd == -1)  
            throw string("SocketTcp: can't create socket.").append(strerror(errno));

        alarm(static_cast<unsigned int>(timeout_sec));
        if (connect(fd, reinterpret_cast<const Sockaddr *>(&sv), sizeof(sv)) < 0)
            throw string("SocketTcp: can't connect socket: ").append(strerror(errno));
        alarm(0);

        if(Socket::alarmOn){
            shutdown(fd, SHUT_RDWR);
            close(fd);
            fd  =  -1;
            throw string("SocketTcp: time exceed.");
        }

        int reuse { 1 };
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(int)) < 0)
            throw string("SocketTcp: can't configure socket SO_REUSEADDR.");
    }

    SocketTcp::~SocketTcp(void){
        if(fd != -1)     
            close(fd);
    }

    void SocketTcp::sendMsg(const Buffer& query, Response& response) anyexcept{

        auto checkResult  { [&](ssize_t result, bool isSend){
            const string fName { isSend ? "SocketTcp::sendMsg:sendto: " : "SocketTcp::sendMsg:recvfrom: " };
            if(Socket::alarmOn){
                shutdown(fd, SHUT_RDWR);
                fd       =  -1;
                wrnMsg.append(fName).append(" time exceed."); 
                timeExc  =  true;
                return;
            }

            if(Socket::sigpipeOn){
                shutdown(fd, SHUT_RDWR);
                fd       =  -1;
                wrnMsg.append(fName).append(" sigpipe received."); 
                return;
            }

            switch(result) {
                case -1:
	                shutdown(fd, SHUT_RDWR);
                    fd  =  -1;
                    if(errno == EAGAIN && rcvResp > 0 && !isSend){
                        wrnMsg.append(fName).append(" recvfrom timeout, partial read.");
                        return;
                    }
                    throw string(fName).append(" error, can't read query response: ").append(strerror(errno));
                case 0:
	                shutdown(fd, SHUT_RDWR);
                    fd  =  -1;
                    if(rcvResp > 0){
                        wrnMsg.append(fName).append(" recvfrom detect close, partial read.");
                        return;
                    }
                    throw string(fName).append(" can't read, socket close on other side.");
                default:
                    if(result < 0 || result > DNS_RESPONSE_TCP_SIZE)
                        throw string(fName).append(" unexpected response size : ").append(to_string(result));
            }
        }};

        alarm(static_cast<unsigned int>(timeout_sec));
        ssize_t   ret   {  ::sendto(fd, query.data(),                           query.size(), 
                                    0,  reinterpret_cast<const Sockaddr*>(&sv), sizeof(sv)) };
        alarm(0);
        checkResult(ret, true);

        response.clear();
        rcvResp  =  0;

        size_t   pos { 0 };
        alarm(static_cast<unsigned int>(timeout_sec));
        ret     =  ::recvfrom(fd, tcpBuffer.data() + pos, tcpBuffer.size() - pos, 0, reinterpret_cast<Sockaddr*>(&sv), &len);
        alarm(0);

        checkResult(ret, false);
        pos              += static_cast<size_t>(ret);
        rcvResp          =  ret - 2;

        size_t declaredLen { ntohs(*(reinterpret_cast<uint16_t*>(tcpBuffer.data()))) };

        while( pos < declaredLen ) {
            alarm(static_cast<unsigned int>(timeout_sec));
            ret     =  ::recvfrom(fd, tcpBuffer.data() + pos, tcpBuffer.size() - pos, 0, reinterpret_cast<Sockaddr*>(&sv), &len);
            alarm(0);

            checkResult(ret, false);
            pos     += static_cast<size_t>(ret);
            rcvResp += ret;
        }

        response.insert(response.end(), tcpBuffer.begin() + 2, tcpBuffer.begin() + rcvResp + 2);
    }

    SocketUdpVerbose::SocketUdpVerbose(ServerId hst)
        :  SocketUdp{hst}
    {}

    void SocketUdpVerbose::sendMsg(const Buffer& query, Response& response)  anyexcept{
       start             =   system_clock::now();
       SocketUdp::sendMsg(query, response);
       end               =   system_clock::now();
       elapsed_seconds   =   end - start;
       cerr << "Elapsed Time: "    << elapsed_seconds.count() << '\n' << '\n'
            << "Response Length: " <<  rcvResp                << '\n'    
            <<  endl;
       trace("Message sent:", query, 0, 12);
       trace("Message received:", response.data(), static_cast<size_t>(rcvResp), 0, 12);
    } 

    SocketUdpPing::SocketUdpPing(ServerId hst)
        :  SocketUdp{hst}
    {
        setCloseOnError(false);
    }

    void SocketUdpPing::sendMsg(const Buffer& query, Response& response)  anyexcept{
       size_t   seq   { 0 };
       while(!signalExit){
           try{
               start             =   system_clock::now();
               SocketUdp::sendMsg(query, response);
               end               =   system_clock::now();
               elapsed_seconds   =   end - start;
               cerr << rcvResp        << " bytes from " << serverid                  
                    << " dns_seq="    << seq           
                    << " time="       << elapsed_seconds.count()  
                    << " ms"          << endl;
           } catch(const string& err){
               static_cast<void>(err);
               cerr <<  " Request timeout for " <<  serverid                  
                    <<  " dns_seq="             <<  seq           
                    <<  endl;
           }
           seq++;
           static_cast<void>(sleep(1));
       }
    } 

    SocketUdpTraceroute::SocketUdpTraceroute(ServerId hst)
        :  SocketUdpConnected{hst}, ttl{1},          icmpFd{-1},         
           maxTtl{200},              port{DNS_PORT},  maxPort{65000}, //TODO: conf
           buffer{},                remoteAddr{}
    {
        setCloseOnError(false);
        sv.sin_port         = htons(port);

        setTimeoutSecs(DNS_DEFAULT_TIMEOUT); 

        if ((icmpFd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) 
            throw string("SocketUdpTraceroute::SocketUdpTraceroute: Can't open icmp socket.");
    }

    SocketUdpTraceroute::~SocketUdpTraceroute(void){
        if(icmpFd != -1) close(icmpFd);
    }

    void SocketUdpTraceroute::setTtl(int newTtl) noexcept{
         ttl = newTtl;
    }

    void SocketUdpTraceroute::applyTtl(void)  noexcept{
         ttl++;
         setsockopt(fd, 0, IP_TTL, &ttl, sizeof(ttl));
    }                                       

    void SocketUdpTraceroute::setMaxTtl(uint8_t newMax) noexcept{
         maxTtl  =  newMax;
    }

    void SocketUdpTraceroute::setPort(uint16_t newPort) noexcept{
         port    =   newPort;
    }

    void SocketUdpTraceroute::setMaxPort(uint16_t newMaxPort) noexcept{
         maxPort  =  newMaxPort ;
    }

    void SocketUdpTraceroute::sendMsg(const Buffer& query, Response& response) anyexcept {
        bool reachDest  { false };
        while(!signalExit && !reachDest){
            applyTtl();
            if( ttl > maxTtl)
               break;

            cerr << "ttl: " << ttl << " from: ";

            for(size_t i=0; i<3; ++i){
                alarm(static_cast<unsigned int>(timeout_sec));
                start             =   system_clock::now();
                ssize_t   ret   {  ::send(fd, query.data(), query.size(), 0) };                            
                alarm(0);
                if(ret == -1 ){ 
                    if(closeOnError){ 
	                   close(fd); 
                       fd  =  -1;
                    }
        
                    if(alarmOn)
                        throw string("Timeout. ");
                    throw string("SocketUdpConnected::sendMsg: can't send the query: ").append(strerror(errno));
                }

                string errMsg("ReadMsg timeout. ");
                socklen_t                len=sizeof(Sockaddr);
                alarm(static_cast<unsigned int>(timeout_sec));
                long int retIcmp   { ::recvfrom(icmpFd, buffer.data(), buffer.size(), 0, &remoteAddr, &len) };
                if(retIcmp == -1 ){ 
                    wrnMsg  =  string("Icmp socket error: ").append(strerror(errno));
                    cerr << "\t     *     ";
                } else {
                    end               =   system_clock::now();
                    elapsed_seconds   =   end - start;
                    // trace("ICMP received:", buffer.data(), static_cast<size_t>(retIcmp), 0, 12);
                    cerr <<  "\t" << inet_ntoa((reinterpret_cast<sockaddr_in*>(&remoteAddr))->sin_addr)
                         <<  "\t("  << elapsed_seconds.count() << "s)";
                }
                alarm(0);

                if(retIcmp == -1 ){ 
                    alarm(static_cast<unsigned int>(timeout_sec));
                    rcvResp     =  ::recvfrom(fd, response.data(), response.size(), 0, &remoteAddr, &len);
                    alarm(0);
                    if(rcvResp == -1){ 
                        if(Socket::alarmOn){
                            wrnMsg   =  "SocketUdpConnected::sendMsg: response time exceed."; 
                            timeExc  =  true;
                        }else{    
                                cerr << "Received: " << string(strerror(errno)) << endl;
                        }
                    }else{
                        reachDest  =  true;
                        cerr <<  "\t" << inet_ntoa((reinterpret_cast<sockaddr_in*>(&remoteAddr))->sin_addr) << "\t(DNS answer)\n";
                        trace("\nDump:", response.data(), static_cast<size_t>(rcvResp), 0, 12);
                        break;
                    }
                }
            }
            cerr << endl;
        }
    }

    SocketTcpVerbose::SocketTcpVerbose(ServerId hst)
        : SocketTcp{hst}
    {
        setTimeoutSecs(DNS_DEFAULT_TIMEOUT); 
    }

    void SocketTcpVerbose::sendMsg(const Buffer& query, Response& response)  anyexcept{
        start            =   system_clock::now();
        SocketTcp::sendMsg(query, response);
        end              =   system_clock::now();
        elapsed_seconds  =   end - start;
        cerr << "Elapsed Time: "    <<  elapsed_seconds.count() << '\n' << '\n' 
             << "Response Length: " <<  rcvResp                 << '\n'
             << endl;
        trace("Message sent:", query, 0, 12);
        trace("Message received:", response.data(), static_cast<size_t>(rcvResp), 0, 12);
    }

} // End Namespace
