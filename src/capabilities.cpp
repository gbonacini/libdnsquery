  namespace capabilities{
  
       Capability::Capability(bool noRoot) 
          : uid{getuid()},       euid{geteuid()},
            gid{getgid()},       egid{getegid()},
            cap{cap_get_proc()}, newcaps{cap}
       {  
           if(noRoot) 
             if(uid == 0 || gid == 0 )
                 throw CapabilityException("Root user or group are not permitted: use a standard user instead.");
       }

       Capability::~Capability(void){
          cap_free(cap);
          cap_free(nullptr);
       }

       void Capability::printStatus(void) const noexcept{
           cerr << "UID: " << to_string(uid)     << " EUID: " << to_string(euid) << '\n'
                << "GID: " << to_string(gid)     << " GID:  " << to_string(egid) << '\n'
                << "Running with capabilities: " << cap_to_text(cap, NULL)       << endl;
       }

       void Capability::getCredential(void) anyexcept{
           uid  = getuid();
           euid = geteuid(); 
           gid  = getgid();
           egid = getegid();
           cap  = cap_get_proc();
           if(cap == nullptr)
               throw CapabilityException(string("Capability error reading credential: ") + strerror(errno));
       }

       void Capability::reducePriv(const string& capText) anyexcept{
           if(prctl(PR_SET_KEEPCAPS, 1) ==  -1)
               throw CapabilityException(string("Capability setting error(a): ") + strerror(errno));
           newcaps                      = cap_from_text(capText.c_str());
           if(setresgid(gid, gid, gid)  ==  -1)
               throw CapabilityException(string("Capability setting error(b): ") + strerror(errno));
           if(setresuid(uid, uid, uid)  ==  -1)
               throw CapabilityException(string("Capability setting error(c): ") + strerror(errno));
           if(cap_set_proc(newcaps)     ==  -1)
               throw WhException(string("Capability setting error(d): ") + strerror(errno));

       }

       CapabilityException::CapabilityException(string& errString){
          :  errorMessage{errString}
       {}
   
       CapabilityException::CapabilityException(string&& errString)
           : errorMessage{ move(errString) }
       {}
    
       const string& CapabilityException::what() const noexcept{
           return errorMessage;
       }

} // End Namespace
