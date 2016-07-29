# Hold-On_DNS
Realization of Hold-On DNS, to protect DNS resolver from DNS poisoning.

Usage:

$ gcc HoldOn_DNS.c -lm -o HoldOn_DNS -std=gnu99

(Ignore the warning about implicit declaration of function 'inet_aton')

$ ./HoldOn_DNS +queryURL

(eg: ./HoldOn_DNS www.google.com)

Test Environment:
Linux Ubuntu 4.4.0-31-generic, 64bit. GCC version 5.3.1

PS. Default DNS server is set to 8.8.8.8 (google-public-dns), you can change it to another ip by modifying the value of serv_ip[] in Hold-On DNS.c and Ping.sh. By the way, if the output always shows "No Reliable Replies Received.", try to compare the "Expected RTT" and "Expected TTL" with real RTT and TTL in replies and alter the parameters "rttRatio" and "ttlRatio" by referring to the following program:

if(real RTT>(1-rttRatio)*Expected RTT&&real RTT<(1+rttRatio)*Expected RTT)
	and(real ttl>(1-ttlRatio)*Expected ttl&&real ttl<(1+ttlRatio)*Expected ttl)

then the program will regard this reply as a reliable reply and show its details. 
