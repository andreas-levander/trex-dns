# No gateway

Need to setup ARP entry on TARGET ex.
`ip neigh add 192.168.0.60 lladdr bc:24:11:2b:c5:31 dev enp6s18 nud permanent`
or if it exists
`ip neigh replace 192.168.0.60 lladdr bc:24:11:2b:c5:31 dev enp6s18 nud permanent`