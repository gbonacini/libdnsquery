#include <trace.hpp>

namespace stringutils{
  using std::cerr;
  using std::endl;
  using std::hex;
  using std::dec;
  using std::setfill;
  using std::setw;
  using std::string;
  using std::vector;

  void  trace(const char* header, const uint8_t* buff, const size_t size,
              size_t begin, size_t end) noexcept{
     cerr << header << '\n' << endl;
 
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
     cerr << '\n' << endl;
  }
 
  void trace(string header) noexcept{
     cerr << header << endl << endl;
  }

  void trace(string header, const vector<uint8_t>* buff,
             size_t begin, size_t end, size_t max) noexcept{
     cerr << header << '\n' << endl;

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
     cerr << '\n' << endl;
  }

  void trace(string header, const vector<uint8_t>& buff,
             size_t begin, size_t end, size_t max) noexcept{
     cerr << header << '\n' << endl;

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
     cerr << '\n' << endl;
  }
} // End Namespace
