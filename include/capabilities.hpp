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

#ifndef  LINUX_CAPABILITIES__BG_HPP
#define  LINUX_CAPABILITIES__BG_HPP

#include <sys/prctl.h>
#include <sys/capability.h>

#include <string>

#include <anyexcept.hpp>

namespace capabilities{

        class Capability{
            public:
                   explicit  Capability(bool noRoot);
                             ~Capability(void);
                   void      printStatus(void)                         const  noexcept;
                   void      getCredential(void)                              anyexcept;
                   void      reducePriv(const std::string& capText)           anyexcept;

            private:
                   uid_t     uid,
                             euid;
                   gid_t     gid,
                             egid;
                   cap_t     cap,
                             newcaps;
        };

        class CapabilityException final{
            public:
               explicit CapabilityException(std::string&  errString);
               explicit CapabilityException(std::string&& errString);   
               const std::string& what(void)                           const  noexcept;
            private:
               std::string errorMessage;
        };

} // End Namespace

#endif
