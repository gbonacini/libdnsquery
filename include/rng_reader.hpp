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

#ifndef DNSCLIENRNG_BG_HPP
#define DNSCLIENRNG_BG_HPP

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <string>
#include <cstdint>
#include <cstring>
#include <cerrno>

#include <anyexcept.hpp>

namespace rngreader{
    static const char * const RAND_FILE       =  "/dev/urandom";

    template<typename T>
    class RngReader{
       public:
           ~RngReader(void);
    
           static const RngReader& getInstance(void)               anyexcept;
           void                    getRndNums(uint8_t* const start, 
                                              size_t num)   const  anyexcept;
           void                    getRndNums(T& buff, size_t start,
                                              size_t num)   const  anyexcept;
       private:
           int    rngFd;
    
           RngReader(void);
           RngReader(RngReader && rng)                 = delete;
           RngReader(RngReader const& rng)             = delete;
           RngReader& operator=(RngReader const& rng)  = delete;
           RngReader& operator=(RngReader && rng)      = delete;
    };

} // End Namespace

#endif
