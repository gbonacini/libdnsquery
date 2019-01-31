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

#include <dns_client.hpp>
#include <safeconversion.hpp>

#ifdef OFFENSIVE_REL
    #ifdef LINUX_OS
       #include <capabilities.cpp>
    #endif
#endif

namespace dnsclient{

    using std::vector;
    using std::string;
    using std::to_string;
    using std::stringstream;
    using std::cerr;
    using std::cout;
    using std::endl;
    using std::getline;
    using std::chrono::time_point;
    using std::chrono::system_clock;
    using std::chrono::duration;
    using std::out_of_range;
    using std::function;
    using std::get;
    using std::make_tuple;
    using std::dec;
    using std::hex;
    using std::regex;
    using std::sregex_token_iterator;
    using std::regex_search;
    using std::smatch;
    using std::pair;
    using std::make_pair;
    using std::stoul;
    using std::setfill;
    using std::setw;
    using std::ifstream;
    using std::ofstream;
    using std::copy;
    using std::istreambuf_iterator;
    using std::ios;

    using networkutils::SocketCreator;
    using networkutils::SocketTypes;

    using safeconv::safeSizeT;
    using safeconv::safeLongT;
    using safeconv::safeUint8T;

    using stringutils::trace;

    DnsBase::DnsBase(void)
        :    queryTypeDescrToClass{ make_pair("std",          QUERY_TYPE::STD_QUERY),
                                    make_pair("dump",         QUERY_TYPE::DUMP_QUERY),
                                    make_pair("ping",         QUERY_TYPE::PING_QUERY),
                                    make_pair("mail",         QUERY_TYPE::MAIL_QUERY),
                                    make_pair("locate",       QUERY_TYPE::LOC_QUERY),
                                    #ifdef OFFENSIVE_REL
                                    make_pair("std-spoofed",  QUERY_TYPE::STD_QUERY_SP),
                                    make_pair("info-spoofed", QUERY_TYPE::INFO_QUERY_SP),
                                    make_pair("mail-spoofed", QUERY_TYPE::MAIL_QUERY_SP),
                                    #endif
                                    make_pair("info",         QUERY_TYPE::INFO_QUERY)
             },
             queryTypeToDescription{ make_pair(QUERY_TYPE::STD_QUERY,      "std"),
                                     make_pair(QUERY_TYPE::DUMP_QUERY,     "dump"),
                                     make_pair(QUERY_TYPE::PING_QUERY,     "ping"),
                                     make_pair(QUERY_TYPE::MAIL_QUERY,     "mail"),
                                     make_pair(QUERY_TYPE::LOC_QUERY,      "locate"),
                                     #ifdef OFFENSIVE_REL
                                     make_pair(QUERY_TYPE::STD_QUERY_SP,   "std-spoofed"),
                                     make_pair(QUERY_TYPE::INFO_QUERY_SP,  "info-spoofed"),
                                     make_pair(QUERY_TYPE::MAIL_QUERY_SP,  "mail-spoofed"),
                                     #endif
                                     make_pair(QUERY_TYPE::INFO_QUERY,     "info")
             },
             queryHeaderConst{
                            //         BITS 
                            // Bytes   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // 0|2,1|3 |              TRANSACTION ID                   |
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                                      0x0b,                    0xad,
                            // 2|4,3|5 |QR|Opcode     |AA|TC|RD|RA|   Z    |   RCODE   |
                            //          |                        |
                                      0b0'0000'0'0'1,          0b0'000'0000,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // 4|6,5|7  |                    QDCOUNT (No. Questions)    |
                                      0x00,                    0x01,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // 6|8,7|9  |                    ANCOUNT (No. RR Query.)     |
                                      0x00,                    0x00,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // 8|10.9|11|                    NSCOUNT (No. RR Auth Sect.)|
                                      0x00,                    0x00,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // 10|12,  |                    ARCOUNT (No. Additional RR)|
                            // 11|13   |                                               |
                                      0x00,                    0x00
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
             },
             queryHeaderLenConst{ 
                            //         BITS 
                            // Bytes   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // 0,  1   |              MESSAGE LEN                      |
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                                      0x00,                    0x00
             },
             queryFooterConst{
                            //         BITS
                            // ELEM    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // 12|14,..|                                               |
                            // ..      /                     QNAME                     /
                            // ..      /                                               /
                                      0x0,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // ..      |                     QTYPE                     |
                                      0x00,                    0x01,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // ..      |                     QCLASS                    |
                                      0x00,                    0x01 
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
             },
             queryFooterTxtConst{
                            //         BITS
                            // ELEM    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // 12|14,..|                                               |
                            // ..      /                     QNAME                     /
                            // ..      /                                               /
                                      0x0,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // ..      |                     QTYPE                     |
                                      0x00,                    0x10,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // ..      |                     QCLASS                    |
                                      0x00,                    0x03 
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
             },
             queryFooterMailConst{
                            //         BITS
                            // ELEM    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // 12|14,..|                                               |
                            // ..      /                     QNAME                     /
                            // ..      /                                               /
                                      0x0,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // ..      |                     QTYPE                     |
                                      0x00,                    0x0f,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // ..      |                     QCLASS                    |
                                      0x00,                    0x01 
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
             },
             queryFooterLocConst{
                            //         BITS
                            // ELEM    0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // 12|14,..|                                               |
                            // ..      /                     QNAME                     /
                            // ..      /                                               /
                                      0x0,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // ..      |                     QTYPE                     |
                                      0x00,                    0x1d,
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
                            // ..      |                     QCLASS                    |
                                      0x00,                    0x01 
                            //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
             },
             queryHeader{queryHeaderConst},
             queryHeaderLen{queryHeaderLenConst},
             queryFooter{queryFooterConst},
             queryFooterTxt{queryFooterTxtConst},
             queryFooterMail{queryFooterMailConst},
             queryFooterLoc{queryFooterLocConst},
             tcpQuery{false},
             activeType{QUERY_TYPE::STD_QUERY},
             socketptr{nullptr},
             sitename{"null"},
             dnsName{"null"},
             #ifdef OFFENSIVE_REL
             spoofing{"null"},
             #endif
             queryTxt{"null"},
             timeoutSecs{3},
             rsp(static_cast<size_t>(networkutils::DNS_RESPONSE_SIZE), 0),
             queryTypeIdx{0},
             queryClassIdx{0},
             responseEndIdx{0},
             queryType{0},
             queryClass{0}
    {}
    
    void  DnsBase::setSite(SiteName site) anyexcept{
        if(site.size() > DNS_MAX_DOMAIN_SIZE)
            throw string("DnsBase::setSite: Domain string too long.");
        try{
            sitename = site;
        }catch(...){
            throw string("DnsBase::setSite: Can't set site name or address.");
        }
    }

    void  DnsBase::setDNSserver(DnsName dns) anyexcept{
        try{
            dnsName = dns;
        }catch(...){
            throw string("DnsBase::setDNSserver: Can't set dns address.");
        }
    }

    template<typename U>
    void  DnsBase::setMask(U mask, U& dest) noexcept{
        dest |= mask;
    }

    template<typename U>
    void  DnsBase::unsetMask(U mask, U& dest) noexcept{
        dest &= ~mask;
    }

    template<typename U>
    void  DnsBase::invertMask(U mask, U& dest) noexcept{
        dest ^= mask;
    }

    template<typename U>
    bool  DnsBase::checkMask(U mask, U dest) const noexcept{
        return dest & mask;
    }

    template<typename U>
    U  DnsBase::getMaskValue(U mask, U orig)  const  noexcept{
          return mask & orig ;
    }

    bool  DnsBase::isTruncated(void) const noexcept {
         return checkMask(DNS_TC, rsp.at(DNS_TC_IDX));
    }

    void   DnsBase::resetHeader(void)  anyexcept{
        try{
            queryHeader  =  queryHeaderConst;
        }catch(...){
            throw string("DnsBase::resetHeader: Can't reset the header.");
        }
    }

    void  DnsBase::setTranId(void) anyexcept{
        const size_t  begin  { static_cast<size_t>((tcpQuery ? DNS_RESP_DATA_TCP_DELTA  : 0)) };
        try{
           RngReaderVectUint8::getInstance().getRndNums(queryAssembl, begin, sizeof(uint16_t));
        }catch(const string& err){
           throw string ("DnsBase::setTranId: Can't set transaction id: ").append(err);
        }
    }

    void  DnsBase::resetFooterStd(void) anyexcept {
        try{
            queryFooter     =  queryFooterConst;
        }catch(...){
            throw string("DnsBase::resetFooterStd: Can't reset the footer.");
        }
    }

    void   DnsBase::resetFooterMail(void)  anyexcept{
        try{
            queryFooterMail  =  queryFooterMailConst;
        }catch(...){
            throw string("DnsBase::resetFooterMail: Can't reset the footer.");
        }
    }

    void   DnsBase::resetFooterLoc(void)  anyexcept{
        try{
            queryFooterLoc =  queryFooterLocConst;
        }catch(...){
            throw string("DnsBase::resetFooterLoc: Can't reset the footer.");
        }
    }

    void DnsBase::resetFooterTxt(void)  anyexcept{
        try{
            queryFooterTxt  =  queryFooterTxtConst;
        }catch(...){
            throw string("DnsBase::resetFooterTxt: Can't reset the footer.");
        }
    }

    size_t  DnsBase::getQueryClassIdx(void) noexcept{
        return queryClassIdx;
    }

    size_t DnsBase::getRespIdx(void) noexcept{
        return  getQueryClassIdx() + sizeof(uint16_t);
    }

    bool  DnsBase::checkPtr(size_t idx, uint16_t& dest) anyexcept{
        try{
            if(checkMask(DNS_PTRS, rsp.at(idx))){
                dest  =  ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + idx)));
                unsetMask(DNS_PTRS_U16, dest);
                return true;
            }else{
                dest  =  0;
                return false;
            }
         }catch(const out_of_range& err){
               throw string("DnsClient::checkPtr - Invalid idx access: ").append(to_string(idx))\
                     .append(" - ").append(err.what());
         }
    }

    void DnsBase::assembleQuery(bool addLen, QUERY_TYPE qtype) anyexcept{
        try{
            queryAssembl.clear();
            if(addLen)
                queryAssembl.insert(queryAssembl.end(), queryHeaderLen.begin(), queryHeaderLen.end());
            queryAssembl.insert(queryAssembl.end(), queryHeader.begin(), queryHeader.end());
                
            stringstream     lineStream(sitename);
            for(string buff; getline(lineStream, buff, STD_SEPARATOR); ) {
                if(buff.size() > DNS_MAX_LABEL_SIZE)
                     throw string(" Label too long: ").append(buff);
                queryAssembl.push_back(static_cast<uint8_t>(buff.size()));
                queryAssembl.insert(queryAssembl.end(), buff.begin(), buff.end());
            }

            switch(qtype){
                case QUERY_TYPE::INFO_QUERY    :
                #ifdef OFFENSIVE_REL
                case QUERY_TYPE::INFO_QUERY_SP :
                #endif
                    queryAssembl.insert(queryAssembl.end(), queryFooterTxt.begin(), queryFooterTxt.end());
                break;
                case QUERY_TYPE::MAIL_QUERY    :
                #ifdef OFFENSIVE_REL
                case QUERY_TYPE::MAIL_QUERY_SP :
                #endif
                    queryAssembl.insert(queryAssembl.end(), queryFooterMail.begin(), queryFooterMail.end());
                break;
                case QUERY_TYPE::LOC_QUERY     :
                    queryAssembl.insert(queryAssembl.end(), queryFooterLoc.begin(), queryFooterLoc.end());
                break;
                case QUERY_TYPE::STD_QUERY     :     
                case QUERY_TYPE::DUMP_QUERY    :     
                case QUERY_TYPE::PING_QUERY    :     
                #ifdef OFFENSIVE_REL
                case QUERY_TYPE::STD_QUERY_SP  :
                #endif
                    queryAssembl.insert(queryAssembl.end(), queryFooter.begin(), queryFooter.end());
            }

            if(addLen){
                uint16_t* tcpSizeHdr  {  reinterpret_cast<uint16_t*>(queryAssembl.data()) };
                *tcpSizeHdr           =  htons(queryAssembl.size() - queryHeaderLenConst.size());
            }
        }catch(const string& err){
           throw string("DnsBase::assembleQuery: ").append(err);
        }catch(...){
           throw string("DnsBase::assembleQuery: unexpected exception.");
        }
    }

    void DnsBase::sendQuery(bool assemble) anyexcept{
        if(tcpQuery)
            sendQueryTcp(assemble);
        else
            sendQueryUdp(assemble);
    }

    void DnsBase::sendQueryTcp(bool assemble) anyexcept{
        tcpQuery    =   true;

        if(assemble){
            try{
               assembleQuery(true, activeType);
            }catch(const string& err){
                throw string("DnsBase::sendQueryTcp: can't assemble query buffer: ").append(err);
            }
            setTranId();
        }

        #if defined __clang_major__ &&  __clang_major__ >= 4 
        #pragma clang diagnostic push 
        #pragma clang diagnostic ignored "-Wswitch-enum"
        #endif

        switch(activeType){
            case QUERY_TYPE::STD_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::TcpSocket);
            break;
            case QUERY_TYPE::DUMP_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::TcpSocketVerbose);
            break;
            case QUERY_TYPE::INFO_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::TcpSocket);
            break;
            case QUERY_TYPE::MAIL_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::TcpSocket);
            break;
            case QUERY_TYPE::LOC_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::TcpSocket);
            break;
            case QUERY_TYPE::PING_QUERY :
                 throw string("DnsClient::sendQueryTcp: ping type requires udp.");
            #ifdef OFFENSIVE_REL
            default:
                 throw string("DnsClient::sendQueryTcp: unexpected dns query type.");
            #endif
        }

        #ifdef __clang__
        #pragma clang diagnostic pop
        #endif

        socketptr->sendMsg(queryAssembl, rsp);

        extractQueryPartFromResponse();
        extractResponse(getRespIdx());
    }

    void DnsBase::sendQueryUdp(bool assemble) anyexcept{

        if(assemble){
            try{
               assembleQuery(false, activeType);
            }catch(const string& err){
                throw string("DnsBase::sendQueryUdp: can't assemble query buffer: ").append(err);
            }
            setTranId();
        }

        switch(activeType){
            case QUERY_TYPE::STD_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::UdpSocket);
            break;
            case QUERY_TYPE::DUMP_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::UdpSocketVerbose);
            break;
            case QUERY_TYPE::PING_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::UdpSocketPing);
            break;
            case QUERY_TYPE::INFO_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::UdpSocket);
            break;
            case QUERY_TYPE::MAIL_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::UdpSocket);
            break;
            case QUERY_TYPE::LOC_QUERY :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::UdpSocket);
            break;                        
            #ifdef OFFENSIVE_REL
            case QUERY_TYPE::STD_QUERY_SP  :
                 socketptr = SocketCreator::getInstance(dnsName, spoofing, timeoutSecs).createSocket(SocketTypes::UdpSocketSp);
            break;
            case QUERY_TYPE::INFO_QUERY_SP :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::UdpSocketSp);
            break;
            case QUERY_TYPE::MAIL_QUERY_SP :
                 socketptr = SocketCreator::getInstance(dnsName, "", timeoutSecs).createSocket(SocketTypes::UdpSocketSp);
            break;
            #endif
        }
        socketptr->sendMsg(queryAssembl, rsp);

        extractQueryPartFromResponse();
        extractResponse(getRespIdx());

        if(isTruncated()){
            socketptr.reset(nullptr);
            sendQueryTcp(assemble);
        }
    }

    void  DnsBase::extractQueryPartFromResponse(void) anyexcept{
       auto resetOnErr  {  [&](){
           queryTypeIdx    =  0;
           queryClassIdx   =  0;
           queryType       =  0;
           queryClass      =  0;
           queryTxt        =  "Error";
       }};

       try{
           stringstream     sstr;
           const size_t     queryStart   { static_cast<size_t>(DNS_RESP_DATA_IDX) };
           string           name;
           queryTypeIdx     =  extractTextFromResponse(queryStart, name);
           sstr << name;
    
           queryClassIdx    =  queryTypeIdx  +  sizeof(uint16_t);
            if((queryClassIdx + 1) >= safeSizeT(socketptr->getRecvLen()))
                throw  string("DnsClient::extractQueryPartFromResponse: Invalid Index: ").append(to_string(queryClassIdx + 1));

           queryType        =  ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + queryTypeIdx)));
           queryClass       =  ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + queryClassIdx)));
           queryTxt         =  sstr.str();
       }catch(const string& err){
           throw  string("DnsClient::extractQueryPartFromResponse: ").append(err);
       }catch(const out_of_range& err){
           resetOnErr();
           throw  string("DnsClient::extractQueryPartFromResponse: Index Error parsing query section in response, rsp len: ")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - ").append(err.what());
       }catch(...){
           resetOnErr();
           throw  string("DnsClient::extractQueryPartFromResponse: Unexpected Error parsing query section in response, rsp len: ").append(to_string(socketptr->getRecvLen()));
       }
    }

    void  DnsBase::extractResponse(size_t mainIdx) anyexcept{
        try{
            size_t  respNum  { 1 },
                    respsTot { getResponsesNo() + getRRAuthNo() }; 
            for(size_t blkIdx{mainIdx}; 
                blkIdx < safeSizeT(socketptr->getRecvLen()) && respNum <= respsTot; 
                ++respNum)
            {
               string  name;
               blkIdx  =  extractTextFromResponse(blkIdx, name);

               if((blkIdx + RSP_START_IDX * sizeof(uint16_t) +  sizeof(uint32_t)) >= safeSizeT(socketptr->getRecvLen()))
                   throw  string("Invalid Index: ")\
                                 .append(to_string(blkIdx + RSP_START_IDX * sizeof(uint16_t) +  sizeof(uint32_t)));

               uint16_t  type    {  ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + blkIdx))) };
    
               blkIdx += sizeof(uint16_t);
               uint16_t  classid {  ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + blkIdx))) };
     
               blkIdx += sizeof(uint16_t);
               uint32_t  ttl     {  ntohl(*(reinterpret_cast<const uint32_t*>(rsp.data() + blkIdx))) };
    
               blkIdx += sizeof(uint32_t);
               uint16_t  datalen {  ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + blkIdx))) };

               blkIdx += sizeof(uint16_t);
               string  datastr;
               switch(type){
                   case RR_TYPES_CNAME:
                       extractTextFromResponse(blkIdx, datastr);
                   break;
                   case RR_TYPES_A:
                       extractAddrFromResponse(blkIdx, datastr);
                   break;
                   case RR_TYPES_NS:
                       extractTextFromResponse(blkIdx, datastr);
                   break;
                   case RR_TYPES_AAAA:
                       extractAddr6FromResponse(blkIdx, datastr);
                   break;
                   case RR_TYPES_SOA:
                       extractSoaTextFromResponse(blkIdx, datastr);
                   break;
                   case RR_TYPES_TXT:
                       extractInfoTextFromResponse(blkIdx, datastr);
                   break;
                   case RR_TYPES_MX:
                       extractMxFromResponse(blkIdx, datastr);
                   break;
                   case RR_TYPES_LOC:
                       extractLocFromResponse(blkIdx, datastr);
                   break;
                   case RR_TYPES_WKS:
                   case RR_TYPES_PTR:
                   case RR_TYPES_SRV:
                   default:
                        datastr = "Error";
                        throw string(" Unsupported RR type: ").append(to_string(type));
               }

               blkIdx          +=  datalen;
               responseEndIdx  =   blkIdx;

               parsedResponse.push_back(make_tuple(name, type, classid, ttl, datalen, datastr));
               if(responseTypeIdx.find(type) != responseTypeIdx.end())
                   responseTypeIdx[type].push_back(parsedResponse.size()-1);
               else
                   responseTypeIdx.emplace(type, vector<size_t>{parsedResponse.size()-1});
        }
       }catch(const out_of_range& err){
           throw  string("DnsBase::extractResponse: Index Error in extractResponse.")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - ").append(err.what());
       }catch(const string& err){
           throw  string("DnsBase::extractResponse: ").append(err);
       }catch(...){
           throw  string("DnsBase::extractResponse: Unexpected Error.");
       }
    }

    void DnsBase::extractLocFromResponse(size_t idx, std::string& result) anyexcept{
        try{
            size_t expectedSize  =  idx + (4 * sizeof(uint8_t)) + ( 2 * sizeof(uint32_t));
            if(rsp.size() < expectedSize - 1)
                throw string("DnsBase::extractLocFromResponse: invalid response format/size.");
            stringstream  sstr;
            sstr << "Ver;" << static_cast<int>(rsp.at(idx));
            idx++;
            sstr << ";Sz;" << static_cast<int>(rsp.at(idx));
            idx++;
            sstr << ";Hp;" << static_cast<int>(rsp.at(idx));
            idx++;
            sstr << ";Vp;" << static_cast<int>(rsp.at(idx));
            idx++; 
            sstr << ";La;" << ntohl(*(reinterpret_cast<const uint32_t*>(rsp.data() + idx )));
            idx += sizeof(uint32_t);
            sstr << ";Lo;" << ntohl(*(reinterpret_cast<const uint32_t*>(rsp.data() + idx )));
            idx += sizeof(uint32_t);
            sstr << ";Al;" << ntohl(*(reinterpret_cast<const uint32_t*>(rsp.data() + idx ))) << ";";

            result = sstr.str();
        }catch(const out_of_range& err){
           throw  string("DnsClient::extractAddrFromResponse: Index Error.")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - ").append(err.what());
        }catch(...){
           throw  string("DnsClient::extractAddrFromResponse: Unexpected Error.");
        }
    }

    void DnsBase::extractAddrFromResponse(size_t ipIdx, std::string& result) anyexcept{
        try{
            stringstream  sstr;
            if( (ipIdx + RSP_ADDR_IDX) >= safeSizeT(socketptr->getRecvLen()))
                throw  string("DnsBase::extractAddrFromResponse: Invalid Index: ").append(to_string(ipIdx));
            sstr << static_cast<int>(rsp.at(ipIdx))   << "." << static_cast<int>(rsp.at(ipIdx + (RSP_ADDR_IDX -2))) << "." 
                 << static_cast<int>(rsp.at(ipIdx + (RSP_ADDR_IDX -1))) << "." << static_cast<int>(rsp.at(ipIdx + RSP_ADDR_IDX));

            result = sstr.str();
        }catch(const out_of_range& err){
           throw  string("DnsClient::extractAddrFromResponse: Index Error.")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - ").append(err.what());
        }catch(...){
           throw  string("DnsClient::extractAddrFromResponse: Unexpected Error.");
        }
    }

    void DnsBase::extractMxFromResponse(size_t ipIdx, std::string& result) anyexcept{
        try{
            if((ipIdx + sizeof(uint16_t)) >= safeSizeT(socketptr->getRecvLen()))
                throw  string("DnsClient::extractMxFromResponse: Invalid Index: ").append(to_string(ipIdx));

            stringstream  sstr;
            sstr << dec << ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + ipIdx )))  << ";";

            string mailserver;
            extractTextFromResponse(ipIdx + sizeof(uint16_t), mailserver);
            sstr << mailserver;
            result = sstr.str();
        }catch(const out_of_range& err){
           throw  string("DnsClient::extractMxFromResponse: Index Error.")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - ").append(err.what());
        }catch(const string& err){
           throw string("DnsClient::extractMxFromResponse: ").append(err);
        }catch(...){
           throw  string("DnsClient::extractMxFromResponse: Unexpected Error.");
        }
    }

    void DnsBase::extractAddr6FromResponse(size_t ipIdx, std::string& result) anyexcept{
        try{
            stringstream  sstr;
            if( (ipIdx + RSP_ADDR6_IDX) >= safeSizeT(socketptr->getRecvLen()))
                throw  string("extractAddr6FromResponse: Invalid Index: ").append(to_string(ipIdx));

            for(size_t inc{0}; inc < (RSP_ADDR6_IDX + 1); ++inc)
                sstr << hex << ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + ipIdx + inc * sizeof(uint16_t))))  << ":";

            result = sstr.str();
            result.pop_back();
        }catch(const out_of_range& err){
           throw  string("DnsClient::extractAddr6FromResponse: Index Error.")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - ").append(err.what());
        }catch(...){
           throw  string("DnsClient::extractAddr6FromResponse: Unexpected Error.");
        }
    }

    void  DnsBase::extractInfoTextFromResponse(size_t txtIdx, string& result)  anyexcept{
       try{
           stringstream  sstr;
           size_t        len  { rsp.at(txtIdx) };

           for(size_t idx { txtIdx + 1 }; idx < txtIdx + 1 + len; ++idx)
                  sstr << rsp.at(idx);

           result = sstr.str();

       }catch(const out_of_range& err){
           throw string("DnsClient::extractInfoTextFromResponse: Index Error parsing resp section in response, rsp len: ")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - ").append(err.what());
       }catch(const string& err){
           throw string("DnsClient::extractInfoTextFromResponse :").append(err);
       }catch(...){
           throw string("DnsClient::extractInfoTextFromResponse: Unexpected Error parsing resp section in response, rsp len: ").append(to_string(socketptr->getRecvLen()));
       }
    }

    void  DnsBase::extractSoaTextFromResponse(size_t txtIdx, string& result)  anyexcept{
       try{
           stringstream  sstr;
           string        reverseLookup;
           extractTextFromResponse(txtIdx, reverseLookup);

           sstr << reverseLookup << ";";

           result = sstr.str();
       }catch(const out_of_range& err){
           throw string("DnsClient::extractSoaTextFromResponse: Index Error parsing resp section in response, rsp len: ")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - ").append(err.what());
       }catch(const string& err){
           throw string("DnsClient::extractSoaTextFromResponse: ").append(err);
       }catch(...){
           throw string("DnsClient::extractInfoTextFromResponse: Unexpected Error parsing resp section in response, rsp len: ").append(to_string(socketptr->getRecvLen()));
       }
    }

    size_t  DnsBase::extractTextFromResponse(size_t txtIdx, string& result)  anyexcept{
       try{
           if(rsp.at(txtIdx) == 0){
               result = "<ROOT>";
               return (txtIdx + sizeof(uint8_t));
           }

           uint16_t      ptr       { 0 };
           bool          localIdx  { true },
                         isPtr     { checkPtr(txtIdx , ptr) };
           if(isPtr)     localIdx  = false;
           size_t        last      { isPtr  ? ptr + 1 + rsp.at(ptr)     : txtIdx + 1 + rsp.at(txtIdx)},
                         idx       { isPtr  ? ptr + 1                   : txtIdx + 1 },
                         next      { isPtr  ? txtIdx + sizeof(uint16_t) : txtIdx + 1 + rsp.at(txtIdx) };
           stringstream  sstr;

           while(true){

                for(;idx < last; ++idx)
                    sstr << rsp.at(idx);

                if(rsp.at( idx) == 0){
                    if(localIdx) next++;
                    break;
                } 
                sstr << "." ;
                isPtr     =  checkPtr(idx, ptr);
                last      =  isPtr  ? ptr + 1 + rsp.at(ptr) : idx + 1 + rsp.at(idx);
                if(localIdx){
                              next = isPtr  ?  next + sizeof(uint16_t) : last ;
                              if(isPtr)     localIdx  = false;
                }
                idx       =  isPtr  ? ptr + 1               : idx + 1;
           }
           result = sstr.str();
           return next;
       }catch(const out_of_range& err){
           throw string("DnsClient::extractTextFromResponse: Index Error parsing resp section in response, rsp len: ")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - ").append(err.what());
       }catch(const string& err){
           throw string("DnsClient::extractTextFromResponse: ").append(err);
       }catch(...){
           throw string("DnsClient::extractTextFromResponse: Unexpected Error parsing resp section in response, rsp len: ").append(to_string(socketptr->getRecvLen()));
       }
    } 

    void  DnsBase::setForceTcp(bool tcp) noexcept{
         tcpQuery     =  tcp;
    }

    size_t  DnsBase::getQueryTypeIdx(void) noexcept{
        return queryTypeIdx;
    }

    size_t  DnsBase::getQuerysNo(void)  anyexcept{
        const size_t idx   { static_cast<size_t>(DNS_QDCOUNT_IDX + (tcpQuery ? DNS_RESP_DATA_TCP_DELTA : 0))};

        if( (idx + 1) >= safeSizeT(socketptr->getRecvLen()))
             throw  string("DnsClient::getQuerysNo: Index Error, rsp len: ")\
                          .append(to_string(socketptr->getRecvLen()))\
                          .append(" - idx: ").append(to_string(idx + 1));
        return ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + idx )));
    }

    size_t  DnsBase::getResponsesNo(void)  anyexcept{
        const size_t idx   { static_cast<size_t>(DNS_ANCOUNT_IDX + (tcpQuery ? DNS_RESP_DATA_TCP_DELTA : 0)) };

        if( (idx + 1) >= safeSizeT(socketptr->getRecvLen()))
            throw  string("DnsClient::getResponsesNo: Index Error, rsp len: ")\
                         .append(to_string(socketptr->getRecvLen()))\
                         .append(" - idx: ").append(to_string(idx + 1));

        return ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + idx)));
    }

    size_t  DnsBase::getRRAuthNo(void) anyexcept{
        const size_t idx   { static_cast<size_t>(DNS_NSCOUNT_IDX + (tcpQuery ? DNS_RESP_DATA_TCP_DELTA : 0)) };

        if( (idx + 1) >= safeSizeT(socketptr->getRecvLen()))
           throw  string("DnsClient::getRRAuthNo: Index Error, rsp len: ")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - idx: ").append(to_string(idx + 1));

        return ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + idx)));
    }

    size_t  DnsBase::getRRAddNo(void)  anyexcept{
        const size_t idx   { static_cast<size_t>(DNS_ARCOUNT_IDX + (tcpQuery ? DNS_RESP_DATA_TCP_DELTA : 0)) };

        if( (idx + 1) >= safeSizeT(socketptr->getRecvLen()))
           throw  string("DnsClient::getRRAddNo: Index Error, rsp len: ")\
                        .append(to_string(socketptr->getRecvLen()))\
                        .append(" - idx: ").append(to_string(idx + 1));

        return ntohs(*(reinterpret_cast<const uint16_t*>(rsp.data() + idx)));
    }

    DnsClient::DnsClient(string dns, string site)
        :     DnsClient()
    {
        setSite(site);
        setDNSserver(dns);
    }

    DnsClient::DnsClient(void)
           : bindVersion{"VERSION.BIND"},
             emptyResponse{"empty response"},
             rRToStringpMap{ make_pair(RR_TYPES_A,      "A"),
                             make_pair(RR_TYPES_NS,     "NS"),
                             make_pair(RR_TYPES_CNAME,  "CNAME"),
                             make_pair(RR_TYPES_SOA,    "SOA"),
                             make_pair(RR_TYPES_WKS,    "WKS"),
                             make_pair(RR_TYPES_PTR,    "PTR"),
                             make_pair(RR_TYPES_MX,     "MX"),
                             make_pair(RR_TYPES_TXT,    "TXT"),
                             make_pair(RR_TYPES_AAAA,   "AAAA"),
                             make_pair(RR_TYPES_LOC,    "LOC"),
                             make_pair(RR_TYPES_SRV,    "SRV")
             },
             stringToRRMap{ make_pair("A",       RR_TYPES_A),
                            make_pair("NS",      RR_TYPES_NS),
                            make_pair("CNAME",   RR_TYPES_CNAME),
                            make_pair("SOA",     RR_TYPES_SOA),
                            make_pair("WKS",     RR_TYPES_WKS),
                            make_pair("PTR",     RR_TYPES_PTR),
                            make_pair("TXT",     RR_TYPES_TXT),
                            make_pair("AAAA",    RR_TYPES_AAAA),
                            make_pair("LOC",     RR_TYPES_LOC),
                            make_pair("SRV",     RR_TYPES_SRV)
             } 
    {}

    const string  DnsClient::rrTypeToString(size_t rrcode) const noexcept{
          auto entry { rRToStringpMap.find(rrcode) };
          return entry != rRToStringpMap.end() ?  entry->second : to_string(rrcode);
    }

    size_t  DnsClient::rrStringToCode(const string& rrstring) const noexcept{
          auto entry { stringToRRMap.find(rrstring) };
          return entry != stringToRRMap.end() ?  entry->second : 0;
    }

    #ifdef OFFENSIVE_REL
          #include "dns_client_enum.cpp"
    #endif

    void  DnsClient::setQueryType(QUERY_TYPE type) noexcept{
         activeType  =  type;
    }

    bool  DnsClient::setQueryType(const string& descr)  noexcept{
         auto  found  { queryTypeDescrToClass.find(descr) };
         if(found == queryTypeDescrToClass.end())
            return false;

         activeType  =  found->second;
         return true;
    }

    #ifdef OFFENSIVE_REL
        void  DnsClient::setSpoofingAddr(const string& spoof) noexcept{
             spoofing     =  spoof;
        }
    #endif

    void  DnsClient::setRecursionDes(bool rec) noexcept{
        if(rec)
            setMask(DNS_RD, queryHeader.at(DNS_RD_IDX));
        else
            unsetMask(DNS_RD, queryHeader.at(DNS_RD_IDX));
    }

    void  DnsClient::setTimeoutSecs(time_t tou) noexcept{
         timeoutSecs  =  tou;
    }

    string DnsClient::reverseQueryHostString(const string& saddr, bool checkFormat) anyexcept{
        const string      revQuerySuffix("in-addr.arpa");
        vector<string>    addr;
        const regex       re("[.]"),
                          reerr("[^0-9.]");

        smatch wrong;
        if(regex_search(saddr,  wrong, reerr))
            throw string("Invalid addr : ").append(saddr);

        sregex_token_iterator it(saddr.begin(), saddr.end(), re, -1);
        sregex_token_iterator reg_end;
        for (; it != reg_end; ++it) 
             addr.push_back(it->str());

        if(checkFormat){
            if(addr.size() != DNS_REVQUERY_SIZE)
                throw string("Invalid addr : ").append(saddr);
    
            for(auto el : addr)
                if(stoul(el) > std::numeric_limits<uint8_t>::max())
                   throw string("Invalid addr elem: ").append(el);
        }
    
        string            buff;
        for(auto itv{addr.crbegin()}; itv != addr.crend(); ++itv)
            buff.append(*itv).append(".");
        buff.append(revQuerySuffix);

        return buff;
    }

    bool  DnsClient::isTimeout(void) const noexcept{
        return socketptr->isTimeout();
    }

    const std::string&  DnsClient::getWarning(void) const noexcept{
        return socketptr->getWarningMsg();
    }

    uint8_t DnsClient::getReturnCode(void)  const noexcept{
        return getMaskValue(DNS_RET.back(), rsp[DNS_RCODE_IDX]);
    }

    double  DnsClient::getElapsedTime(void) const noexcept{
        return socketptr->getElapsedTime();
    }

    const string&  DnsClient::getQueryTxtFromResp(void)  const noexcept{
        return queryTxt;
    }

    const string&  DnsClient::getLastTxtFromResp(void)  const noexcept{
        if(parsedResponse.size() != 0)
            return get<PARSED_RESP_DATA_IDX>(parsedResponse.back());
        else
            return emptyResponse;
    }

    const string  DnsClient::getAllTxtFromResp(void)  const noexcept{
        string buff;
        if(parsedResponse.size() != 0){
            for(auto& el : parsedResponse)
                buff.append(get<PARSED_RESP_NAME_IDX>(el)).append(";")\
                    .append(to_string(get<PARSED_RESP_TYPE_IDX>(el))).append(";")\
                    .append(to_string(get<PARSED_RESP_CLASS_IDX>(el))).append(";")\
                    .append(to_string(get<PARSED_RESP_TTL_IDX>(el))).append(";")\
                    .append(get<PARSED_RESP_DATA_IDX>(el)).append("\n");
            return buff;
         }else{
            return emptyResponse;
         }
    }

    const string   DnsClient::getAllTxtSpecTypeResp(const std::string& type) const noexcept{
        auto         entry  { responseTypeIdx.find(rrStringToCode(type)) };
        string       buff;

        if(entry != responseTypeIdx.end()){
            for(auto& el: entry->second)
               buff.append(get<PARSED_RESP_DATA_IDX>(parsedResponse[el])).append("\n");
            return buff;
        }else{
            return emptyResponse;
        }
    }

    const string  DnsClient::getOnextSpecTypeResp(const std::string& type) const noexcept{
        auto         entry  { responseTypeIdx.find(rrStringToCode(type)) };

        if(entry != responseTypeIdx.end())
            return get<PARSED_RESP_DATA_IDX>(parsedResponse[entry->second.back()]);

        return emptyResponse;
    }

    ssize_t DnsClient::getRespLength(void) const noexcept{
        return socketptr->getRecvLen();
    }

    void DnsClient::assembleQuery(bool addLen, QUERY_TYPE qtype) anyexcept{
         if(qtype == QUERY_TYPE::INFO_QUERY)
             sitename = bindVersion;
         try{
            DnsBase::assembleQuery(addLen, qtype);
         }catch(const string& err){
            throw string("DnsBase::assembleQuery: sitename: ").append(sitename)\
                         .append(": ").append(err);
         }
    }

    const std::string  DnsClient::getDnsErrorTxt(uint16_t errcode) anyexcept {
        const vector<string> err {
                /* 0 */    "NoError: No Error",
                /* 1 */    "FormErr: Format Error.",
                /* 2 */    "ServFail: Server Failure.",
                /* 3 */    "NXDomain: Non-Existent Domain.",
                /* 4 */    "NotImp: Not Implemented.",
                /* 5 */    "Refused: Query Refused.",
                /* 6 */    "YXDomain: Name Exists when it should not.",
                /* 7 */    "YXRRSet: RR Set Exists when it should not.",
                /* 8 */    "NXRRSet: RR Set that should exist does not.",
                /* 9 */    "NotAuth: Server Not Authoritative for zone.",
                /* 10 */   "NotZone: Name not contained in zone.",
                /* 11 */   "Available: for assignment",
                /* 12 */   "Available: for assignment",
                /* 13 */   "Available: for assignment",
                /* 14 */   "Available: for assignment",
                /* 15 */   "Available: for assignment",
                /* 16 */   "BADSIG/BADVERS: TSIG Signature Failure/Bad OPT Version.",
                /* 17 */   "BADKEY: Key not recognized.",
                /* 18 */   "BADTIME: Signature out of time window.",
                /* 19 */   "BADMODE: Bad TKEY Mode.",
                /* 20 */   "BADNAME: Duplicate key name.",
                /* 21 */   "BADALG: Algorithm not supported.",
                /* 22 */   "BADTRUC: Bad Truncation." 
        };

        const string group1("Available for assignment");
        const string group2("Private Use");
        const string group3("Available for assignment");
        const string group4("IETF Reserved");

        if(errcode < GROUP_ZERO_LIM){
             return err.at(errcode); 
        }else if(errcode <  GROUP_ONE_LIM){
             return group1;
        }else if(errcode <  GROUP_TWO_LIM){
             return group2;
        }else if(errcode <  GROUP_THREE_LIM){
             return group3;
        }

        return group4;
    }

    #ifdef OFFENSIVE_REL
        #include "dns_client_shell.cpp"
    #endif

} // End Namespace
