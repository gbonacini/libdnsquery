#include <rng_reader.hpp>
#include <safeconversion.hpp>

namespace rngreader{

    using std::string;
    using safeconv::safeSSizeT;

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
        if(rngFd != -1)
            close(rngFd);
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
        if(ret == -1 || ret != safeSSizeT(num))
           throw string("Error reading from rng device: ").append(RAND_FILE).append(" - ").append(strerror(errno));
    }

    template<typename T>
    void  RngReader<T>::getRndNums(T& buff, size_t start, size_t num) const  anyexcept{
        if((buff.size() - 1) < start)
            throw string("Invalid starting index of rng buffer.");
        if((buff.size() - 1) < (start + num))
            throw string("Attempt to write beyond the end of rng buffer");

        ssize_t ret { read(rngFd, buff.data() + start, num) };
        if(ret == -1 || ret != safeSSizeT(num))
           throw string("Error reading from rng device: ").append(RAND_FILE).append(" - ").append(strerror(errno));
    }

} // End Namespace

#include "rng_reader_impl.cpp"
