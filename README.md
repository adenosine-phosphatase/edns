# edns
Check DNS compatibility with Extension DNS (EDNS(0))

build: gcc edns.c -out edns

usage is: edns <domain name> <DNS server IP address> [dnssec | txt]
  
If the DNS response is <512, the code displays the message that there's insufficient data. (payload must be >512 bytes>

If response payload is >512 it checks if the  "Truncated" bit in the DNS "Flags" attribute from server is set and tells if the server behaviour is compatible with EDNS.

Essentially, the server should continue to use UDP even for packets >512 bytes, and not switch over to TCP instead.
