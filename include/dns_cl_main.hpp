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

#ifndef DNSCLIENT_MAIN_BG_HPP
#define DNSCLIENT_MAIN_BG_HPP

#include <config.h>

#include <dns_client.hpp>
#include <parseCmdLine.hpp>

void paramError(const char* progname, const char* err)  noexcept    __attribute__ ((noreturn));
void versionInfo(void)                                  noexcept    __attribute__ ((noreturn));
bool isAnAddr(const std::string& param)                 anyexcept;
const dnsclient::EnumerationRanges
     createEnumerationList(std::string& epar)           anyexcept;

#endif
