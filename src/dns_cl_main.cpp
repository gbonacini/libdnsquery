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
// ----------------------------------------------------------------

#include <dns_cl_main.hpp>

using namespace std;
using namespace dnsclient;
using namespace parcmdline;

int main(int argc, char** argv){

    constexpr char         flags[]    { "ie:a:u:Ad:s:S:T:lfht:VrX" };
    constexpr time_t       DEF_TIMEO  { 3   },
                           MAX_TIMEO  { 120 };
    int                    ret        { 0   };

    try{
        #ifdef OFFENSIVE_REL
            #ifdef LINUX_OS
                capabilities::Capability cpb(true);
                cpb.reducePriv("cap_net_raw+ep");
                cpb.getCredential();
                cpb.printStatus();
            #endif
        #endif

        ParseCmdLine pcl(argc, argv, flags);
        if(pcl.getErrorState()){
            string exitMsg{string("Invalid  parameter or value").append(pcl.getErrorMsg())};
            paramError(argv[0], exitMsg.c_str());
        }

        if(!pcl.isSet('d') && !pcl.isSet('s') && !pcl.isSet('t') && 
           !pcl.isSet('f') && !pcl.isSet('l') && !pcl.isSet('A') && 
           !pcl.isSet('a') && !pcl.isSet('u') && !pcl.isSet('T') && 
           #ifdef OFFENSIVE_REL
               !pcl.isSet('e') && !pcl.isSet('r') && !pcl.isSet('S') &&
               !pcl.isSet('i') && 
           #endif
           !pcl.isSet('X') && !pcl.isSet('h') && !pcl.isSet('V') )
              paramError(argv[0], "No valid parameter specified");

        #ifdef OFFENSIVE_REL
            if( pcl.isSet('i') && (pcl.isSet('s') || pcl.isSet('e') ||
                pcl.isSet('t') || pcl.isSet('f')  || pcl.isSet('S') ||
                pcl.isSet('l') || pcl.isSet('A')  || pcl.isSet('a') ||
                pcl.isSet('u') || pcl.isSet('T')  || pcl.isSet('r') ||
                pcl.isSet('h') || pcl.isSet('V')) || pcl.isSet('X'))
                  paramError(argv[1], "-i (interactive node) doesn't require other parameters.");
        #endif

        if(pcl.isSet('h')) paramError(argv[0], "");
        if(pcl.isSet('V')) versionInfo();

        #ifdef OFFENSIVE_REL
            if(pcl.isSet('i')){
                DnsClientShell dcs;
                dcs.loop();
                return 0;
            }
        #endif

        if(pcl.isSet('X') && (!pcl.isSet('d') || !pcl.isSet('s') ))
              paramError(argv[0], "-X  requires -d and -s.");

        if( pcl.isSet('X') && (pcl.isSet('e') || pcl.isSet('t') || 
            pcl.isSet('f')  || pcl.isSet('S') || pcl.isSet('l') || 
            pcl.isSet('A')  || pcl.isSet('a') || pcl.isSet('u') || 
            pcl.isSet('T')  || pcl.isSet('r') || pcl.isSet('h') || 
            pcl.isSet('i')  || pcl.isSet('V')) )
              paramError(argv[0], "-X  requires only -d and -s.");

        if(pcl.isSet('X') ){
            DnsTraceroute dcs(pcl.getValue('d'), pcl.getValue('s'));
            dcs.loop();
            return 0;
        }

        size_t filterNoOut { 0 };
        if(pcl.isSet('A'))  filterNoOut++;
        if(pcl.isSet('a'))  filterNoOut++;
        if(pcl.isSet('u'))  filterNoOut++;
        if(filterNoOut > 1 )
            paramError(argv[0], "-A, -a and -u are mutually exclusive.");

        #ifdef OFFENSIVE_REL
            if(pcl.isSet('S') && ( pcl.isSet('e')     ||  pcl.isSet('f') || 
                                   filterNoOut != 0   ||  pcl.isSet('l')) )
                paramError(argv[0], "-S isn't compatible with  -e, -A, -a, -u, -l or -f.");

            if(pcl.isSet('S') ){
                // compat: standard(default), info, mail
                if( pcl.isSet('t') && ( pcl.getValue('t').compare("dump")   != 0 ||
                                        pcl.getValue('t').compare("locate") != 0 ||  
                                        pcl.getValue('t').compare("ping") != 0  )) 
                     paramError(argv[0], "-S isn't compatible with these -t options: dump, locate, ping.");
            }
        #endif

        if(!pcl.isSet('d'))
            paramError(argv[0], "You must specify -d with an address of a DNS.");

        #ifdef OFFENSIVE_REL
            if(pcl.isSet('s') && pcl.isSet('e'))
                paramError(argv[0], "-s and -e are mutually exclusive.");
        #endif

        #ifdef OFFENSIVE_REL
            if(!pcl.isSet('s') && !pcl.isSet('e'))
        #else
            if(!pcl.isSet('s'))
        #endif
            if( pcl.isSet('t') && ( pcl.getValue('t').compare("info") != 0) ) 
                paramError(argv[0], "You must specify -s with a name of a site,"\
                                    " (i.e. www.wikipedia.org), -e with a range (i.e. '192.100-150)");
        
        string   dns{pcl.getValue('d')},
                 site{     isAnAddr(pcl.getValue('s')) 
                             ? dnsclient::DnsClient::reverseQueryHostString(pcl.getValue('s')) 
                                 : pcl.getValue('s')};
        time_t   timeo{    pcl.isSet('T') 
                             ? ( stol(pcl.getValue('T')) <= MAX_TIMEO && stol(pcl.getValue('T')) > 0
                                 ? stol(pcl.getValue('T')) 
                                 : DEF_TIMEO )
                             : DEF_TIMEO};

        DnsClient   dnscl(dns);
        dnscl.setTimeoutSecs(timeo);

        #ifdef OFFENSIVE_REL
            if(pcl.isSet('S')){
                dnscl.setSpoofingAddr(pcl.getValue('S'));
                if(!dnscl.setQueryType("std-spoofed"))
                     paramError(argv[0], "Invalid query type.");
            }

            if(pcl.isSet('e')){
                string rgxbuff { pcl.getValue('e') };
                dnscl.enumerate(createEnumerationList(rgxbuff));
                return 0;
            }
        #endif

        if(pcl.isSet('t')){
            string qtype { pcl.getValue('t') };
            #ifdef OFFENSIVE_REL
                if(pcl.isSet('S')) qtype.append("-spoofed");
            #endif
            if(!dnscl.setQueryType(qtype))
                 paramError(argv[0], "Invalid query type.");
        }

        dnscl.setForceTcp(pcl.isSet('f'));
        dnscl.setSite(site);
        #ifdef OFFENSIVE_REL
            if(pcl.isSet('r'))
                dnscl.setRecursionDes(false);
        #endif
        dnscl.sendQuery();
        if(dnscl.isTimeout())
            cerr << dnscl.getWarning() << '\n';

        if(pcl.isSet('l') && !pcl.isSet('t')) 
            cerr << "Response Length: " << dnscl.getRespLength() << '\n';

        #ifdef OFFENSIVE_REL
            if(pcl.isSet('t') && !pcl.isSet('S')){
        #else
            if(pcl.isSet('t')){
        #endif
           cerr << "\nDNS Lookup: Query: " <<  dnscl.getQueryTxtFromResp() 
                << "\nDNS Lookup: Resp: " ;
        }

        if(pcl.isSet('A'))
            cout << dnscl.getAllTxtFromResp() <<  '\n';
        else if(pcl.isSet('a'))
            cout << dnscl.getAllTxtSpecTypeResp(pcl.getValueUpper('a')) <<  '\n';
        else if(pcl.isSet('u'))
            cout << dnscl.getOnextSpecTypeResp(pcl.getValueUpper('u')) <<  '\n';
        #ifdef OFFENSIVE_REL
        else if(!pcl.isSet('S'))
        #else
        else
        #endif
            cout << dnscl.getLastTxtFromResp() <<  '\n';

        if(dnscl.getReturnCode() != 0){
            ret = 1;
            cerr << "DNS response notifies an arror code: " 
                 << dnscl.getDnsErrorTxt(dnscl.getReturnCode()) << '\n';
        }

    }catch(const string& err){
        ret = 1;
        cerr << "Exception: " << err << '\n';
    #ifdef OFFENSIVE_REL
    #ifdef LINUX_OS
       }catch(const capabilities::CapabilityException& ex){
            cerr << "Exception: " << ex.what() << '\n';
    #endif
    #endif
    }catch(...){
        ret = 1;
        cerr << "Exception: Unexpected\n";
    }

	return ret;
}

void paramError(const char* progname, const char* err) noexcept{

   if(err != nullptr) cerr << err << "\n\n";

   cerr << progname   << " - a cmd line dns query tool.                                   \n"
                      << " GBonacini - (C) 2018-2023                                      \n"                                      
        << "Syntax:                                                                       \n"                                                                    
        #ifdef OFFENSIVE_REL
        << "       "  << progname << " [ -d dns_address ] [-s site_name | -e ranges]      \n"
                                  << " [-t qtype] [-f] [-S fake_sender]                   \n"
                                  << " [-l] [-A | -a type | -u type] [-T secs] [-r] [-X]  \n"     
                                  << " | [-i]                                             \n"     
        #else
        << "       "  << progname << " [ -d dns_address ] [-s site_name ]                 \n"
                                  << " [-t qtype] [-f]                                    \n"
                                  << " [-l] [-A | -a type | -u type] [-T secs] [-X]       \n"     
        #endif
        << "       "              << " | [-h] | [-V]                                      \n\n"   
        << "       "  << "-t query type.                                                  \n" 
        << "       "  << "   Supported types: standard(default), dump, ping, info         \n" 
        << "       "  << "                    mail, locate                                \n" 
        << "       "  << "-A Print all responses.                                         \n" 
        << "       "  << "-a response type. Print all responses of a given type.          \n" 
        << "       "  << "    Supported types: a, aaaa, ns, cname, soa, wks, ptr          \n" 
        << "       "  << "                     txt, loc, srv                              \n" 
        << "       "  << "-u response type. Print a single response of a given type:      \n" 
        << "       "  << "    Supported types: see -a.                                    \n" 
        << "       "  << "-T secs. Set timeout to <secs> seconds.                         \n" 
        << "       "  << "-X set trace mode: all the hops will be printed to verify       \n" 
        << "       "  << "   the responder.                                               \n" 
        << "       "  << "-l print response length.                                       \n"                                     
        << "       "  << "-f force tcp query.                                             \n"                                          
        << "       "  << "-d an address of a DNS.                                         \n"                                       
        << "       "  << "-s a name of a site (i.e. www.wikipedia.org)                    \n"                  
        #ifdef OFFENSIVE_REL
        << "       "  << "-i interactive / batch mode                                     \n" 
        << "       "  << "-S fake address. This option permits to spoof a sender address. \n"
        << "       "  << "-r unset RD bit (cache snoop attack).                           \n"                         
        << "       "  << "-e range.  Enumerate all the reverse lookups in the given range.\n"
        #endif
        << "       "  << "-h print this help message.                                     \n"                                   
        << "       "  << "-V version information.                                         \n\n";

   exit(1);
}

void versionInfo(void) noexcept{
   cerr << PACKAGE << " version: " VERSION << '\n';
   exit(1);
}

bool isAnAddr(const string& param) anyexcept{
   try{
      const regex  addressFilter{"^([0-9]{1,3}[.]){3}[0-9]{1,3}$"};

      return regex_search(param, addressFilter) ? true : false;
   }catch(...){
       throw string("Error testing -s data type.");
   }
}

const dnsclient::EnumerationRanges createEnumerationList(string& epar) anyexcept{
   try{
      const regex  addressRangeFilter{"^([0-9]{1,3}([\\-]{1}[0-9]{1,3})*){1}([.]{1}[0-9]{1,3}([\\-]{1}[0-9]{1,3})*){0,3}$"};

      if(!regex_search(epar, addressRangeFilter)) 
           throw string("Error testing -e data type: invalid format string");

      dnsclient::EnumerationRanges octs {"1", "254", "0", "255", 
                                         "0", "255", "1", "254"};
      const  regex                 oct{"[^.]+)"};   
      const  regex                 ranges{"[^\\-]+)"};   
      size_t                       idx { 0 };
      for(auto regit     {  sregex_iterator(epar.begin(), epar.end(), oct) }; 
               regit    !=  sregex_iterator() && idx < octs.size();
               ++regit, idx+=2) {
          string                           buff { regit->str() };
          regex_iterator<string::iterator> regxitinn( buff.begin(), buff.end(), ranges );
          regex_iterator<string::iterator> regxendinn;
          regxitinn != regxendinn ? octs[idx]    =  regxitinn->str() : octs[idx]    = buff;
          ++regxitinn;
          regxitinn != regxendinn ? octs[idx+1]  =  regxitinn->str() : octs[idx+1]  = buff;
      }

      return octs;
   }catch(const string& err){
       throw err;
   }catch(...){
       throw string("Unexpected error testing -e data type.");
   }

}
