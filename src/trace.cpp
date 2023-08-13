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

#include <trace.hpp>

namespace stringutils{
  using std::cerr,
        std::hex,
        std::dec,
        std::setfill,
        std::setw,
        std::string,
        std::vector;

  void  trace(const char* header, const uint8_t* buff, const size_t size,
              size_t begin, size_t end) noexcept{
     cerr << header << "\n\n"; 
 
     bool last  { false }, 
          first { false };
     for (size_t i { 0 }; i < size; i += 16) {
        cerr << setfill('0') << setw(5) << dec << i << ":  ";
        for (size_t j { i }; j < i + 16; j++) {
           if(end !=0){
              if(j == begin ){cerr <<  "\033[7m"; first = true;}
              if(j == end   ){cerr <<  "\033[0m"; last  = true;}
           }
           if(j < size)
              cerr << setfill('0') << setw(2) << hex
                   << static_cast<int>(buff[j]) << " ";
           else cerr << "   ";
        }
        if(first){cerr <<  "\033[0m"; }
        cerr << ' ';
        for (size_t j { i }; j < i + 16; j++) {
           if(end !=0){
              if((last || j == begin)){cerr <<  "\033[7m"; last  = false; }
              if(j == end            ){cerr <<  "\033[0m"; last  = false; }
           }
           if(j < size){
              if((buff[j] > 31) && (buff[j] < 128) && (buff[j] != 127))
                 cerr << buff[j] ;
              else cerr << '.' ;
           }
        }
        first = false;
        cerr << '\n';
     }
     cerr << "\n\n";
  }
 
  void trace(auto header) noexcept{
     cerr << header << "\n\n";
  }
 
  void trace(auto header, const vector<uint8_t>* buff,
             size_t begin, size_t end, size_t max) noexcept{
     cerr << header << "\n\n";

     size_t len    { max ? max : buff->size() };
     bool   last   { false }, 
            first  { false };
     for (size_t i { 0 }; i < len; i += 16) {
        cerr << setfill('0') << setw(5) << dec << i << ":  ";
        for (size_t j { i }; j < i + 16; j++) {
           if(end !=0){
              if(j == begin ){cerr <<  "\033[7m"; first = true;}
              if(j == end   ){cerr <<  "\033[0m"; last  = true;}
           }
           if(j < len)
              cerr << setfill('0') << setw(2) << hex
                   << static_cast<int>(buff->at(j)) << ' ';
           else cerr << "   ";
        }
        if(first){cerr <<  "\033[0m"; }
        cerr << ' ';
        for (size_t j { i }; j < i + 16; j++) {
           if(end !=0){
              if(last && !first   ){cerr << "\033[7m"; last  = false; }
              if(j == begin       ){cerr << "\033[7m"; first = false; }
              if(j == end         ){cerr << "\033[0m"; last  = false; }
           }
           if(j < len){
              if((buff->at(j) > 31) && (buff->at(j) < 128) && (buff->at(j) != 127))
                 cerr << buff->at(j) ;
              else cerr << '.' ;
           }
        }
        first = false;
        cerr << '\n';
     }
     cerr << "\n\n";
  }

  void trace(auto header, const vector<uint8_t>& buff,
             size_t begin, size_t end, size_t max) noexcept{
     cerr << header << "\n\n";

     size_t len    { max ? max : buff.size() };
     bool   last   { false }, 
            first  { false };
     for (size_t i { 0 }; i < len; i += 16) {
        cerr << setfill('0') << setw(5) << dec << i << ":  ";
        for (size_t j { i }; j < i + 16; j++) {
           if(end !=0){
              if(j == begin ){cerr <<  "\033[7m"; first = true;}
              if(j == end   ){cerr <<  "\033[0m"; last  = true;}
           }
           if(j < len)
              cerr << setfill('0') << setw(2) << hex
                   << static_cast<int>(buff.at(j)) << ' ';
           else cerr << "   ";
        }
        if(first){cerr <<  "\033[0m"; }
        cerr << ' ';
        for (size_t j { i }; j < i + 16; j++) {
           if(end !=0){
              if(last && !first   ){cerr << "\033[7m"; last  = false; }
              if(j == begin       ){cerr << "\033[7m"; first = false; }
              if(j == end         ){cerr << "\033[0m"; last  = false; }
           }
           if(j < len){
              if((buff.at(j) > 31) && (buff.at(j) < 128) && (buff.at(j) != 127))
                 cerr << buff.at(j) ;
              else cerr << '.' ;
           }
        }
        first = false;
        cerr << '\n';
     }
     cerr << "\n\n";
  }

   template  void trace(string& header) noexcept;
   template  void trace(const char* header) noexcept;
   template  void trace(string& header, const vector<uint8_t>* buff, size_t begin, size_t end = 0, size_t max) noexcept;
   template  void trace(const char* header, const vector<uint8_t>* buff, size_t begin, size_t end = 0, size_t max) noexcept;
   template  void trace(string&  header, const vector<uint8_t>& buff, size_t begin, size_t end, size_t max ) noexcept;
   template  void trace(const char* header, const vector<uint8_t>& buff, size_t begin, size_t end, size_t max ) noexcept;

} // End Namespace
