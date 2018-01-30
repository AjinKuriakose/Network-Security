from scapy.all import *
import time
import datetime
import dpkt
import sys
import argparse


def print_spoof_details(dns_seg,correct_ip,spoofed_ip):
	timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S.%f')
	print(timestamp+" DNS poisoning attempt")
	print("TXID ",dns_seg.id," Request ",dns_seg.qd[0].qname)
	print("Answer1 ",correct_ip)
	print("Answer2 ",spoofed_ip)
	print ("\n")
 
def dns_sniff(packet):   	
	dns_seg = packet[DNS]
	txnId = dns_seg.id
	curr = []
	if dns_seg.qd[0].qtype == 1 and dns_seg.qd[0].qclass == dpkt.dns.DNS_IN and dns_seg.qr == 1 and dns_seg.ancount > 0 :
		if txnId not in txnIDs.keys():
			for i in xrange(0,dns_seg.ancount):
				if dns_seg.an[i].type ==1 :
					curr.append(dns_seg.an[i].rdata)
			txnIDs[txnId] = curr
		else:
			prev_ip = txnIDs[txnId]
			# Append the current list of ips to the dictionary
			for i in xrange(0,dns_seg.ancount):
				if dns_seg.an[i].type ==1 :
					curr.append(dns_seg.an[i].rdata)
			is_similar = any(i in prev_ip for i in curr) 
			if not is_similar:
				print_spoof_details(dns_seg,prev_ip,curr)


def arg_parser():
	parser = argparse.ArgumentParser('dnsinject.py', add_help=False)
	parser.add_argument("-i", metavar="<Interface>")
	parser.add_argument("-r", metavar="<Trace file>")
	parser.add_argument('expression',nargs='*', action="store")
	args = parser.parse_args()
	return args.i, args.r, args.expression


if __name__ == '__main__':
	interface, tracefile, expression = arg_parser()
	bpf_expression = 'udp src port 53'
	global txnIDs
	txnIDs = {}
	try:
		if interface and tracefile :
			print ("Please specify either interface or tracefile")
			sys.exit()
		if interface is None:
			interface = conf.iface
		if expression:
			bpf_expression += ' and ' + ''.join(expression)
		if tracefile :
			sniff(offline = tracefile, filter = bpf_expression, prn=dns_sniff)
		else :
			sniff(iface=interface, filter = bpf_expression, prn=dns_sniff)
	except AttributeError:
		print "Usage : dnsdetect [-i interface] [-r tracefile] expression"
