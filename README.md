# DNS Requests Generator

Generate DNS requests to a DNS server.

Can use plain text or a file with a list of domains or domain and DNS query type list.

## Features

- Generate DNS requests to a DNS server.
- Different protocols supported: UDP, TCP, and Unix Socket.
- Can use plain text or a file with a list of domains or domain and DNS query type list.
- Statistics about the requests sent.

## Usage

```bash
./zReqGen -file=1000-domains -socket=/tmp/dns_server.sock -protocol=socket
```

```bash
./zReqGen -upstream=127.0.0.1:5302 -file=queries-big.txt -protocol=udp
```
