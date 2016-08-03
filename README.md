# Hold-On_DNS
Realization of Hold-On DNS, to protect DNS resolver from DNS poisoning.

Usage:
1.Server:

$su and input the password to become the super user

# gcc HoldOn_DNSServer.c -lm -o HoldOn_DNSServer -std=gnu99

# ./HoldOn_DNSServer

2.Client:

$ gcc DNSClient.c -o DNSClient

$ ./DNSClient <Domain name> <HoldOn DNS Server IP Address>

(I use the IP of my own PC,eg. ./DNSClient www.google.com 192.168.221.100)

BTW, you can compare the output of the command "nslookup <Domain name> <DNS Server IP>" with my program to see the effect of Hold-On Technology.

Test Environment:
Linux Ubuntu 4.4.0-31-generic, 64bit. GCC version 5.3.1

PS. Default DNS server is set to 8.8.8.8 (google-public-dns), you can change it to another ip by modifying the value of serv_ip[] in Hold-On_DNSServer.c and Ping.sh. By the way, if the output always shows "No Reliable Replies Received.", try to compare the "Expected RTT" and "Expected TTL" with real RTT and TTL in replies and alter the parameters "rttRatio" by referring to the following program:

if(real RTT>(1-rttRatio)*Expected RTT&&real RTT<(1+rttRatio)*Expected RTT)
	and(real ttl==Expected TTL))

then the program will regard this reply as a reliable reply and show its        	details. 
