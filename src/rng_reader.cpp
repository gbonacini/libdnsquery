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

#include <rng_reader.hpp>
#include <Types.hpp>

#include <cerrno>
#include <cstring>

namespace rngreader{

    using std::string,
          typeutils::safeSsizeT;

    template<typename T>
    RngReader<T>::RngReader(void)
        : rngFd{-1}
    {
        rngFd =  open(RAND_FILE, O_RDONLY);
        if(rngFd == -1)
           throw string("Can't open: ").append(RAND_FILE);
    }

    template<typename T>
    RngReader<T>::~RngReader(void){
        if(rngFd != -1) close(rngFd);
    }

    template<typename T>
    const RngReader<T>& RngReader<T>::getInstance(void) anyexcept{
        #if defined __clang_major__ &&  __clang_major__ >= 4 
        #pragma clang diagnostic push 
        #pragma clang diagnostic ignored "-Wexit-time-destructors"
        #endif

        static  RngReader  rng;

        #ifdef __clang__
        #pragma clang diagnostic pop
        #endif

        return  rng;
    }

    template<typename T>
    void  RngReader<T>::getRndNums(uint8_t* const start, size_t num)  const  anyexcept{
        ssize_t ret { read(rngFd, start, num) };
        if(ret == -1 || ret != safeSsizeT(num))
           throw string("Error reading from rng device: ").append(RAND_FILE).append(" - ").append(strerror(errno));
    }

    template<typename T>
    void  RngReader<T>::getRndNums(T& buff, size_t start, size_t num) const  anyexcept{
        if((buff.size() - 1) < start)
            throw string("Invalid starting index of rng buffer.");
        if((buff.size() - 1) < (start + num))
            throw string("Attempt to write beyond the end of rng buffer");

        ssize_t ret { read(rngFd, buff.data() + start, num) };
        if(ret == -1 || ret != safeSsizeT(num))
           throw string("Error reading from rng device: ").append(RAND_FILE).append(" - ").append(strerror(errno));
    }

} // End Namespace

#include "rng_reader_impl.cpp"
