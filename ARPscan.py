#! /usr/bib/python


########## Description ##########
# This script only work on linux platform.
# It can finding all hosts in network.
# Script language: Python2.7
# Test on: Linux kali
# Coded by: Sha2ow_M4st3r
#################################


# NOTE: You should change gateway from 86 line. (last octed should be removed)
# NOTE: You should change IP address from 129 line.


# Import all necessary modules
import commands
import subprocess
import netifaces
import platform
import socket
import time
import sys
import re


# Global variable
Time = time.asctime(time.localtime(time.time()))


# Clean terminal
def Clear_terminal():
	if "Linux" not in platform.platform():
		print "[-] Sorry, this script only work on linux platform :("
		sys.exit()
	else:
		subprocess.call("clear", shell=True)
		Print_banner()


def Print_banner():
	print """

    _    ____  ____                                    
   / \  |  _ \|  _ \ ___  ___ __ _ _ __    _ __  _   _ 
  / _ \ | |_) | |_) / __|/ __/ _` | '_ \  | '_ \| | | |
 / ___ \|  _ <|  __/\__ \ (_| (_| | | | |_| |_) | |_| |
/_/   \_\_| \_\_|   |___/\___\__,_|_| |_(_) .__/ \__, |
                                          |_|    |___/ Coded by: Sha2ow_M4st3r"""




# Finding interfaces
def Interfaces():
	global MAC
	global Interface_use

	Interfaces = commands.getoutput("ls /sys/class/net")
	Interfaces = Interfaces.replace("\n", "-")

	try:
		Interface_use = commands.getoutput("ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)'")
		ADDR = netifaces.ifaddresses(Interface_use)
	except:
		print "[-] Can't find any interfaces !"
		print "[#] Time:",Time
		sys.exit()

	print "\n+----------------------------------------------------+"
	print "|               Finding all interfaces               |"
	print "+----------------------------------------------------+"
	print "| [+] All interfaces: ", Interfaces
	print "| [+] Interface in use: ", Interface_use
	print "| [+]",Interface_use,"interface was selected"
	print "+----------------------------------------------------+\n"

	Interface_MAC = str(ADDR[netifaces.AF_LINK])
	MAC = Interface_MAC[47:64].upper()




# Create an IP addr
def Create_HOST_ID():
	HOST_ID = "192.168.1." # Enter your gateway here (important: last octed should be removed)
	for Adding_host in range(1,256):
		IP = HOST_ID + str(Adding_host)
		ARP_encapsulate(IP)


def Create_socket():
	global S

	try:
		S = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))   # 0x0806 ---> ARP Protocol
	except socket.error as msg:
		print "[-] Socket creation error:", str(msg)
		sys.exit()
	except:
		print "[#] Retry for create socket..."
		Create_socket()



# Ethernet encapsulation
def Ethernet_encapsulate():
	global Ethernet_header
	global SRC_MAC

	SRC_MAC = MAC.replace(":","").decode("hex")
	DST_MAC = "\xff\xff\xff\xff\xff\xff"
	Ether_TYPE = "\x08\x06" # ARP

	Ethernet_header = DST_MAC + SRC_MAC + Ether_TYPE




# ARP encapsulation
def ARP_encapsulate(IP):
	HDW_TYPE = "\x00\x01"      # ---> (1) Ethernet
	Protocol_TYPE = "\x08\x00" # ---> (8) IPv4
	HWD_length = "\x06"        # ---> 6
	Protocol_length = "\x04"   # ---> 4
	OP_CODE = "\x00\x01"       # ---> (1) Request

	DST_MAC = "\x00\x00\x00\x00\x00\x00"
	SRC_IP = socket.inet_aton("192.168.1.10")  # Set your private IP here
	DST_IP = socket.inet_aton(IP)

	ARP_header = HDW_TYPE + Protocol_TYPE + HWD_length + Protocol_length + OP_CODE + SRC_MAC + SRC_IP + DST_MAC + DST_IP

	Packet = Ethernet_header + ARP_header

	Send_Recv(Packet)



# Sending ARP request and reciving ARP reply
def Send_Recv(Packet):
	COUNT = 1
	while COUNT != 0:
		COUNT = COUNT - 1
		try:
			# Sending ARP request
			Create_socket()
			S.bind((Interface_use, socket.htons(0x0806)))
			S.send(Packet)

			# Recving ARP reply
			Create_socket()
			S.settimeout(0.5)
			Response = S.recvfrom(4096)

			Target_MAC = Response[0][6:12].encode("hex")
			Target_MAC = ":".join(re.findall("..", Target_MAC)).upper()
			Target_IP = socket.inet_ntoa(Response[0][28:32])


			print "[Target]:",Target_IP,"------>",Target_MAC

		except socket.timeout:
			continue
		except socket.error as msg:
			print "[-] Socket creation error:", str(msg)
			sys.exit()
		except KeyboardInterrupt:
			print "\n[-] Script stopped. You press the CTRL+C"
			print "[#] Now Time:",Time
			sys.exit()
		except:
			print "[#] Retry send and reciving..."
			Send_Recv()



# Using all functions
def Main():
	Clear_terminal()
	Interfaces()
	Ethernet_encapsulate()
	Create_socket()
	print "[#] Scanning start at:",Time,"(2min and 15sec to full scan)\n"
	print "+----------------------------------------------------+"
	Create_HOST_ID()


Main()