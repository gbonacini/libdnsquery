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
#include <sys/uio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#ifdef OFFENSIVE_REL
    #include <readline/readline.h>
    #include <readline/history.h>
#endif

#include <fstream>
#include <array>
#include <vector>
#include <string>
#include <sstream>
#include <cstdint>
#include <tuple>
#include <functional>
#include <memory>
#include <regex>

#include <anyexcept.hpp>
#include <trace.hpp>
#include <network.hpp>

#ifdef LINUX_OS
    #include <atomic>
    #include <capabilities.hpp>
#endif

#include <rng_reader.hpp>

extern "C" {
  void libdnsquery_is_present(void);
}

extern template class rngreader::RngReader<std::vector<uint8_t>>;

namespace dnsclient {

    enum  ERR_GROUPS : uint16_t { GROUP_ZERO_LIM = 23,     GROUP_ONE_LIM    = 3'841,
                                  GROUP_TWO_LIM  = 4'096,  GROUP_THREE_LIM  = 65'535  };

    enum  RSP_IDXS   : size_t   { RSP_ADDR_IDX   =  3,     RSP_ADDR6_IDX   =  7,     
                                  RSP_START_IDX  =  3                                 };

    enum  DNS_CONSTS : size_t  { DNS_RESP_DATA_IDX       =  12,
                                 DNS_ENUM_RANGES         =  8,
                                 DNS_REVQUERY_SIZE       =  4,
                                 DNS_MAX_LABEL_SIZE      =  63,
                                 DNS_MAX_DOMAIN_SIZE     =  253};

    constexpr size_t             DNS_RESP_DATA_TCP_DELTA =  sizeof(uint16_t);

    enum DNS_HEADER_IDX { DNS_TRANID_IDX   =  0,
                          DNS_FLAGS_IDX    =  2,
                          DNS_QR_IDX       =  2,    DNS_OPCODE_IDX  =  2,
                          DNS_AA_IDX       =  2,    DNS_TC_IDX      =  2,
                          DNS_RD_IDX       =  2,    DNS_RA_IDX      =  3,
                          DNS_Z_IDX        =  3,    DNS_RCODE_IDX   =  3,
                          DNS_QDCOUNT_IDX  =  4,
                          DNS_ANCOUNT_IDX  =  6,
                          DNS_NSCOUNT_IDX  =  8,
                          DNS_ARCOUNT_IDX  =  10};

    //         BITS                    |
    // Bytes   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    //         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    // 2|4,3|5 |QR|Opcode     |AA|TC|RD|RA|   Z    |   RCODE   |

    // QR      : Query (0), Response (1)
    const uint8_t               DNS_QR       =    0b1000'0000;    // Query
    // OPCODE  : Standard query(0), Inverse query(1), 
    //           Server status request(2), Reserved for future use(3-15)
    enum  DNS_OPCODE_MASKS_IDX {REVERSE,  STATUS,  REV_3,  REV_4,
                                REV_5,    REV_6,   REV_7,  REV_8,
                                REV_9,    REV_10,  REV_11, REV_12,
                                REV_13,   REV_14,  REV_15, ALL};

    const std::array<uint8_t,15>DNS_OPCODE     {{ 0b0000'1000,    // Reverse Query
                                                  0b0001'0000,    // Status Req
                                                  0b0001'1000,    // Reserved 3
                                                  0b0010'0000,    // Reserved 4
                                                  0b0010'1000,    // Reserved 5
                                                  0b0011'0000,    // Reserved 6
                                                  0b0011'1000,    // Reserved 7
                                                  0b0100'0000,    // Reserved 8
                                                  0b0100'1000,    // Reserved 9
                                                  0b0101'0000,    // Reserved 10
                                                  0b0101'1000,    // Reserved 11
                                                  0b0110'0000,    // Reserved 12
                                                  0b0110'1000,    // Reserved 13
                                                  0b0111'0000,    // Reserved 14
                                                  0b0111'1000    // Reserved 15
                                                }};  

    // AA      : Server is An Authority for the domain(1), Server isn’t An Authority(0)
    const uint8_t              DNS_AA     =       0b0000'0100;    // Auth
    // TC      : Short(0), Truncated(1)
    const uint8_t              DNS_TC     =       0b0000'0010;    // TRUNC
    // RD      : No Recursion(0), Recursion Desired(1)
    const uint8_t              DNS_RD     =       0b0000'0001;    // RECUR. DESIRED
    // RA      : Recursion Available(1), No Recursion Available(0)
    const uint8_t              DNS_RA     =       0b1000'0000;    // RECUR. AVAIL.   
    // Z       : Reserved, zero for queries and responses.        
    const std::array<uint8_t,7>DNS_Z    {{
                                             0b0001'0000,
                                             0b0010'0000,
                                             0b0011'0000,
                                             0b0100'0000,
                                             0b0101'0000,
                                             0b0110'0000,
                                             0b0111'0000
                                         }};
    // RCODE   : Return Code
    //           0               No error condition
    //           1               Format error    - Unable to interpret the query.
    //           2               Server failure  - The server was unable to process the query 
    //           3               Name Error      - this code signifies that the name referenced 
    //                                             in the query does not exist.
    //           4               Not Implemented - The name server does the requested kind of query
    //           5               Refused         - The name server refuses to perform the specified 
    //                                             operation for policy reasons.  
    //           6-15            Reserved        - For future use.

    const std::array<uint8_t,15>DNS_RET        {{ 0b0000'0001,    
                                                  0b0000'0010,    
                                                  0b0000'0011,   
                                                  0b0000'0100,  
                                                  0b0000'0101, 
                                                  0b0000'0110,   
                                                  0b0000'0111,  
                                                  0b0000'1000,  
                                                  0b0000'1001, 
                                                  0b0000'1010,   
                                                  0b0000'1011,  
                                                  0b0000'1100, 
                                                  0b0000'1101,
                                                  0b0000'1110,  
                                                  0b0000'1111  
                                                }};  

    // const uint8_t             DNS_RET          =       0b0000'1111;            // RETURN 

    const uint8_t             DNS_PTRS         =       0b11'000000;            // POINTER
    const uint16_t            DNS_PTRS_U16     =       0b11'00000000000000;    // POINTER

    static const char         STD_SEPARATOR    =  '.';

    using ResponseStr         =  std::string;
    enum  RESP_RECORD_IDX     {  PARSED_RESP_NAME_IDX,   PARSED_RESP_TYPE_IDX,
                                 PARSED_RESP_CLASS_IDX,  PARSED_RESP_TTL_IDX,
                                 PARSED_RESP_LEN_IDX,    PARSED_RESP_DATA_IDX};
    using ParsedRespRecord    =  std::tuple<std::string, uint16_t, uint16_t, uint32_t, uint16_t, std::string>;
    using ParsedResponse      =  std::vector<ParsedRespRecord>;
    using RRToStringpMap      =  std::map<size_t, std::string>;
    using ResponseTypeIdx     =  std::map<size_t, std::vector<size_t>>;
    using StringToRRMap       =  std::map<std::string, size_t>;
    using Query               =  std::vector<uint8_t>;
    using DnsName             =  std::string;
    using SiteName            =  std::string;
    using RngReaderVectUint8  =  rngreader::RngReader<std::vector<uint8_t>>;
    using SocketPtr           =  std::unique_ptr<networkutils::Socket>;
    using EnumerationRanges   =  std::array<std::string, dnsclient::DNS_ENUM_RANGES>;
    using CmdLineInterpMap    =  std::map<std::string, std::function<int(void)>>;

    enum  RR_TYPES            { RR_TYPES_NULL=0,
                                RR_TYPES_A=1,        RR_TYPES_NS=2, 
                                RR_TYPES_CNAME=5,    RR_TYPES_SOA=6,
                                RR_TYPES_WKS=11,     RR_TYPES_PTR=12,
                                RR_TYPES_MX=15,      RR_TYPES_TXT=16,
                                RR_TYPES_AAAA=28,    RR_TYPES_LOC=29,
                                RR_TYPES_SRV=33};
 
    enum class QUERY_TYPE    {  STD_QUERY,     DUMP_QUERY,     PING_QUERY,     INFO_QUERY, 
                                #ifdef OFFENSIVE_REL
                                STD_QUERY_SP,                                  INFO_QUERY_SP,
                                MAIL_QUERY_SP,
                                #endif
                                MAIL_QUERY,    LOC_QUERY
                             };
    
    using QTypeDescToClass    =  std::map<std::string, QUERY_TYPE>;
    using QTypeToDescript     =  std::map<QUERY_TYPE, std::string>;

    class BitMaskHdlr{
        public:
           static void              setMask(auto mask, auto& dest)                                      noexcept;
           static void              unsetMask(auto mask,   auto& dest)                                  noexcept;
           static void              invertMask(auto mask,   auto& dest)                                 noexcept;
           static bool              checkMask(const auto mask, const auto dest)                         noexcept;
           static auto              getMaskValue(const auto mask, const auto orig)                      noexcept;
    };

    class DnsBase{
        public:
          DnsBase(void);

          void              sendQuery(bool assemble=true)                                        anyexcept;
          bool              isTruncated(void)                                           const    noexcept;
          void              setForceTcp(bool tcp=true)                                           noexcept;
          void              setSite(SiteName site)                                               anyexcept;
          void              setDNSserver(DnsName dns)                                            anyexcept;

        protected: 
           QTypeDescToClass         queryTypeDescrToClass;
           QTypeToDescript          queryTypeToDescription;
           const Query              queryHeaderConst,
                                    queryHeaderLenConst,
                                    queryFooterConst,
                                    queryFooterTxtConst,
                                    queryFooterMailConst,
                                    queryFooterLocConst;
           Query                    queryHeader,
                                    queryHeaderLen,
                                    queryFooter,
                                    queryFooterTxt,
                                    queryFooterMail,
                                    queryFooterLoc,
                                    queryAssembl;
           bool                     tcpQuery;
           QUERY_TYPE               activeType;
           SocketPtr                socketptr;
           SiteName                 sitename;
           DnsName                  dnsName;
           #ifdef OFFENSIVE_REL
           std::string              spoofing;
           #endif
           std::string              queryTxt;
           time_t                   timeoutSecs;
           networkutils::Response   rsp;
           size_t                   queryTypeIdx,
                                    queryClassIdx,
                                    responseEndIdx;
           uint16_t                 queryType,
                                    queryClass;
           ParsedResponse           parsedResponse;
           ResponseTypeIdx          responseTypeIdx;


           void              setTranId(void)                                                     anyexcept;

           void              resetHeader(void)                                                   anyexcept;
           void              resetFooterStd(void)                                                anyexcept;
           void              resetFooterTxt(void)                                                anyexcept;
           void              resetFooterMail(void)                                               anyexcept;
           void              resetFooterLoc(void)                                                anyexcept;

           void              assembleQuery(bool addLen=false,
                                           QUERY_TYPE qtype=QUERY_TYPE::STD_QUERY)               anyexcept;

           void              extractQueryPartFromResponse(void)                                  anyexcept;
           size_t            extractTextFromResponse(size_t txtIdx, std::string& result)         anyexcept;

           void              sendQueryTcp(bool assemble)                                         anyexcept;
           void              sendQueryUdp(bool assemble)                                         anyexcept;

           void              extractResponse(size_t mainIdx)                                     anyexcept;
           void              extractSoaTextFromResponse(size_t txtIdx, std::string& result)      anyexcept;
           void              extractInfoTextFromResponse(size_t txtIdx, std::string& result)     anyexcept;
           void              extractAddrFromResponse(size_t ipIdx, std::string& result)          anyexcept;
           void              extractLocFromResponse(size_t ipIdx, std::string& result)           anyexcept;
           void              extractMxFromResponse(size_t ipIdx, std::string& result)            anyexcept;
           void              extractAddr6FromResponse(size_t ipIdx, std::string& result)         anyexcept;

           size_t            getQueryClassIdx(void)                                              noexcept;
           size_t            getRespIdx(void)                                                    noexcept;
           bool              checkPtr(size_t idx, uint16_t& dest)                                anyexcept;

           size_t            getQueryTypeIdx(void)                                               noexcept;
           size_t            getQuerysNo(void)                                                   anyexcept;
           size_t            getResponsesNo(void)                                                anyexcept;
           size_t            getRRAuthNo(void)                                                   anyexcept;
           size_t            getRRAddNo(void)                                                    anyexcept;
    };

    class DnsClient : public DnsBase {
        public:
           explicit            DnsClient(std::string dns, std::string site="");
                               DnsClient(void);
           #ifdef OFFENSIVE_REL
           void                enumerate(EnumerationRanges rangeLst, bool feedback=false)       anyexcept;
           #endif
           void                setQueryType(QUERY_TYPE type=QUERY_TYPE::STD_QUERY)              noexcept;
           bool                setQueryType(const std::string& descr)                           noexcept;
           void                setRecursionDes(bool rec)                                        noexcept;
           void                setTimeoutSecs(time_t tou)                                       noexcept;
           #ifdef OFFENSIVE_REL
           void                setSpoofingAddr(const std::string& spoof)                        noexcept;
           #endif
           static std::string  reverseQueryHostString(const std::string& saddr,
                                                      bool checkFormat=false)                   anyexcept;
           const std::string&  getQueryTxtFromResp(void)                               const    noexcept;
           const std::string&  getLastTxtFromResp(void)                                const    noexcept;
           const std::string   getAllTxtFromResp(void)                                 const    noexcept;
           const std::string   getAllTxtSpecTypeResp(const std::string& type)          const    noexcept;
           const std::string   getOnextSpecTypeResp(const std::string& type)           const    noexcept;
           uint16_t            getQueryType(void)                                      const    noexcept;
           uint16_t            getQueryClass(void)                                     const    noexcept;
           uint8_t             getReturnCode(void)                                     const    noexcept;
           ssize_t             getRespLength(void)                                     const    noexcept;
           const std::string&  getWarning(void)                                        const    noexcept;
           double              getElapsedTime(void)                                    const    noexcept;
           bool                isTimeout(void)                                         const    noexcept;
           const std::string   rrTypeToString(size_t rrcode)                           const    noexcept;
           size_t              rrStringToCode(const std::string& rrstring)             const    noexcept;
           static
           const std::string   getDnsErrorTxt(uint16_t errcode )                                anyexcept;
    
        private:
           SiteName                 bindVersion;
           const std::string        emptyResponse;
           RRToStringpMap           rRToStringpMap;
           StringToRRMap            stringToRRMap;

        protected:

           void              assembleQuery(bool addLen=false, 
                                           QUERY_TYPE qtype=QUERY_TYPE::STD_QUERY)               anyexcept;
    };

    class DnsTraceroute : public DnsClient {
          void              sendQuery(bool assemble=true)                                        anyexcept = delete;
          bool              isTruncated(void)                                           const    noexcept  = delete;
          void              setForceTcp(bool tcp=true)                                           noexcept  = delete;

        public:
           explicit         DnsTraceroute(std::string dns, std::string site="");
           void             loop(void)                                                           anyexcept;
        
        private:
           networkutils::SocketUdpTraceroute  socketUdpTraceroute;
    };

    #ifdef OFFENSIVE_REL
        #include <dns_client_shell.hpp>
    #endif

} // End Namespace

