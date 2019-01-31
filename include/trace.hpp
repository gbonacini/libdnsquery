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

#ifndef  TRACE_DNSCLIENT_BG_HPP
#define  TRACE_DNSCLIENT_BG_HPP

#include <cstdint>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>

#ifndef NOTRACE
#define TRACE(...)  trace(__VA_ARGS__) 
#else
#define TRACE(...)  
#endif

namespace stringutils{

void      trace(std::string header)                                                       noexcept;
void      trace(std::string header, const std::vector<uint8_t>* buff,
                size_t begin = 0, size_t end = 0, size_t max = 0 )                        noexcept;
void      trace(std::string header, const std::vector<uint8_t>& buff,
                size_t begin = 0, size_t end = 0, size_t max = 0 )                        noexcept;
void      trace(const  char*  header, const uint8_t* buff, const size_t size = 0,
                size_t begin = 0, size_t end = 0 )                                        noexcept;

} //End Namespace

#endif
