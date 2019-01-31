lib_LTLIBRARIES = libdnsquery.la

libdnsquery_la_SOURCES   = dns_client.cpp network.cpp parseCmdLine.cpp rng_reader.cpp trace.cpp 
libdnsquery_la_LDFLAGS   = -version-info 1:0:0  
libdnsquery_la_CPPFLAGS  = -I../include

bin_PROGRAMS            = dnsquery
dist_man_MANS           = ../doc/dnsquery.1
# dist_bin_SCRIPTS = 

nobase_include_HEADERS  = ../include/anyexcept.hpp ../include/dns_cl_main.hpp ../include/dns_client.hpp ../include/network.hpp ../include/parseCmdLine.hpp ../include/rng_reader.hpp ../include/trace.hpp 
dnsquery_SOURCES        = dns_cl_main.cpp
dnsquery_CPPFLAGS       = 
dnsquery_LDADD          = libdnsquery.la

ACLOCAL_AMFLAGS = -I m4


