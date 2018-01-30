# Network-Security
This repository holds the assignments and project works done for the course CSE508- Network Security(Fall 2017), taken by  Prof. Michalis Polychronakis 

### Assignment 1: Passive Network Monitoring

Purpose of this assignment is to get familiar with passive network traffic
monitoring and analysis. Tcpdump is probably the most popular and widely used
passive network monitoring tool. It is built on top of the Libpcap packet
capture library and can capture and display packet headers and payloads either
from a network interface or a network trace file. The task is to analyze
a network trace file and answer various questions.

### Assignment 2: Passive Network Monitoring

Develop a passive network monitoring application
written in C (or C++, but no other language is acceptable) using the libpcap
packet capture library. Your program, called 'mydump', will capture the
traffic from a network interface in promiscuous mode (or read the packets from
a pcap trace file) and print a record for each packet in its standard output,
much like a simplified version of tcpdump. The user should be able to specify
a BPF filter for capturing a subset of the traffic, and/or a string pattern
for capturing only packets with matching payloads.

### Assignment 3: Plugboard Proxy

The task here is to  develop a "plugboard" proxy for adding an extra
layer of protection to publicly accessible network services.

Consider for example the case of an SSH server with a public IP address. No
matter how securely the server has been configured and how strong keys are
used, it might suffer from a zero day vulnerability that allows remote code
execution even before the completion of the authentication process. This could
allow attackers to compromise the server even without having proper
authentication credentials. The Heartbleed OpenSSL bug is a recent example of
such a serious vulnerability against SSL/TLS.

The plugboard proxy you are going to develop, named 'pbproxy', adds an extra
layer of encryption to connections towards TCP services. Instead of connecting
directly to the service, clients connect to pbproxy (running on the same
server), which then relays all traffic to the actual service. Before relaying
the traffic, pbproxy *always* decrypts it using a static symmetric key. This
means that if the data of any connection towards the protected server is not
properly encrypted, then it will turn into garbage before reaching the
protected service.

Attackers who might want to exploit a zero day vulnerability in the protected
service will first have to know the secret key for having a chance to
successfully deliver their attack vector to the server. This of course assumes
that the plugboard proxy does not suffer from any vulnerability itself. Given
that its task and its code are much simpler compared to an actual service
(e.g., an SSH server), its code can be audited more easily and it can be more
confidently exposed as a publicly accessible service.

Clients who want to access the protected server should proxy their traffic
through a local instance of pbroxy, which will encrypt the traffic using the
same symmetric key used by the server. In essence, pbproxy can act both as
a client-side proxy and as server-side reverse proxy.

Your program should conform to the following specification:

pbproxy [-l port] -k keyfile destination port

  -l  Reverse-proxy mode: listen for inbound connections on <port> and relay
      them to <destination>:<port>

  -k  Use the symmetric key contained in <keyfile> (as a hexadecimal string)
  
  
### Assignment 4: DNS Packet Injection  

This utility has the following 2 components
1) an on-path DNS packet injector, and
2) a passive DNS poisoning attack detector.

Part 1:

The DNS packet injector you are going to develop, named 'dnsinject', will
capture the traffic from a network interface in promiscuous mode, and attempt
to inject forged responses to selected DNS A requests with the goal to poison
the resolver's cache.

Your program should conform to the following specification:

dnsinject [-i interface] [-h hostnames] expression

-i  Listen on network device <interface> (e.g., eth0). If not specified,
    dnsinject should select a default interface to listen on. The same
    interface should be used for packet injection.

-h  Read a list of IP address and hostname pairs specifying the hostnames to
    be hijacked. If '-h' is not specified, dnsinject should forge replies for
    all observed requests with the local machine's IP address as an answer.
    
<expression> is a BPF filter that specifies a subset of the traffic to be
monitored. This option is useful for targeting a single or a set of particular
victims.
