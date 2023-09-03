# DNSResolver
Python iterative DNS Client & Resolver for IPV4 DNS Queries.

Client.py is a standard DNS IPV4 querier that generates IPV4 DNS queries of types A, CNAME, NS, MX & PTR in accordance with RFC 1034 & RFC 1035 which specify a universal standard for DNS Queries used by many DNS Resolvers such as Google DNS Resolver (8.8.8.8) & Cloudfare DNS Resolver (1.1.1.1).
# Client Usage

```Usage: python3 Client.py [resolver_ip] [resolver_port] [name] [type] [timeout=5]```

[resolver_ip]: Resolver IP address. For standard usage of Resolver.py running locally, use localhost(127.0.0.1). 

[resolver_port]: Port resolver is listening on. 

[name]: value of query. E.g: To fetch IPV4 A records for google.com, set [name] to "google.com". For PTR queries set name to the IP address to be queried. 

[type]: Type of DNS Query. Client supports A, CNAME, NS, MX & PTR currently. 

[timeout=5]: Set a custom timeout period. Optional argument to set the amount of time waiting for a response from a DNS resolver. Default value is 5.

