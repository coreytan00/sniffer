import socket
import struct
import sys
import time
import datetime

def getVHL(data):
	VHL = data
	version = VHL >> 4
	header_length = VHL % 0xF
	return version, header_length

#type of service
def getTOS(data): 
	#make a dictionary
	precedence = {0:"Routine", 1:"Priority", 2:"Immediate", 3:"Flash", 4:"Flash override", 5:"CRITIC/ECP", 6:"Internetwork control", 7:"Network control"}
	delay = {0:"Normal delay", 1: "low delay"}
	throughput = {0:"Normal throughput", 1:"High throughput"}
	reliability = {0: "Normal reliability", 1:"High reliability"}
	cost = {0: "Normal monetary cost", 1: "Minimum monetary cost"}

	#bit shift
	D = data & 0x10
	D >>= 4
	T = data & 0x8
	T >>= 3
	R = data & 0x4
	R >>= 2
	M = data & 0x2
	M >>= 1

	sep = "\n\t\t"
	TOS = precedence[data >> 5] + sep + delay[D] + sep + throughput[T] + sep + reliability[R] + sep + cost[M]
	return TOS

def getFlags(data):
	flagR = {0: '0 - Reserved bit'} #should always be 0
	flagDF = {0: '0 - Fragment if necessary', 1: '1 - Do not fragment'}
	flagMF = {0: '0 - Last Fragment', 1: '1 - More Fragments'}

	R = data & 0x8000
	R >>= 15
	DF = data & 0x4000
	DF >>= 14
	MF = data & 0x2000
	MF >>= 13

	sep = "\n\t\t"
	flags = flagR[R] + sep + flagDF[DF] + sep + flagMF[MF]
	return flags

def main():
	#create the raw socket
	#raw socket allows bypass of tcp/udp layer and communicate with network ip layer
	conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)	

	#bind to public interface
	#conn.bind(('10.0.0.9', 0))
	conn.bind(('10.0.0.9', 0))
	
	#include IP headers
	conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
	
	#receive all packages
	conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

	#try:
	f = open("sniffer.txt", "w")

	#instead of running forever, use flags and indicate time in seconds.
	# -t = forever
	timeflag = "-t"
	try:
		timeflag = abs(int(sys.argv[1]))
	except ValueError:
		if timeflag != "-t":
			print("please enter a number.")
	except IndexError:
		# make it run forever
		print("running default '-t'")

	totalpacketsize = 0
	count = 0

	def captureProcedure():
		data, addr = conn.recvfrom(65565)
		unpackedData = struct.unpack('!BBHHHBBH4s4s', data[:20])

		version, header_length = getVHL(unpackedData[0])

		TOS = unpackedData[1]
		totalLength = unpackedData[2]
		ID = unpackedData[3]
		flags = unpackedData[4]
		fragmentOffset = unpackedData[4] & 0x1FFFF
		TTL = unpackedData[5]
		protocol = unpackedData[6]
		checksum = unpackedData[7]
		src = socket.inet_ntoa(unpackedData[8])
		dest = socket.inet_ntoa(unpackedData[9])

		info = "An IP packet with size" + str(totalLength) + " captured at " + str(datetime.datetime.now().time()) + "\n"
		info += "Raw Data:" + str(data) + "\n"
		info += "Parsed Data: \n"
		info += "Version:\t" + str(version) + "\n"
		info += "Header Length:\t" + str(header_length) + "bytes\n"
		info += "Type of Service:\n\t\t" + getTOS(TOS)  + "\n"
		info += "ID:\t\t" + str(hex(ID)) + "\n"
		info += "Flags:\n\t\t" + getFlags(flags) + "\n"
		info += "Fragment Offset:" + str(fragmentOffset) + "\n"
		info += "TTL:\t\t" + str(TTL) + "\n"
		info += "Protocol:\t" + str(protocol) + "\n"
		info += "Checksum:\t" + str(checksum) + "\n"
		info += "Source:\t\t" + str(src) + "\n"
		info += "Destination:\t" + str(dest) + "\n"
		info += "Payload:\n" + str(data[20:]) + "\n"
		info += "\n"

		f.write(info)

		return totalLength

	if timeflag == "-t":
		now = time.time()
		while True:
			#add keyboard press later
			totalpacketsize += captureProcedure()
			count += 1
		end = time.time()
		timeflag = end - now
	else:
		now = time.time()
		timer = 0
		while timer <= timeflag: #will there be any threading issue?
			totalpacketsize += captureProcedure()
			count += 1
			end = time.time()
			timer = end - now
	f.close()
	conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
	print("Process finished after {} seconds".format(timeflag))
	print("{} packets captured".format(count))
	print("{} Mb of data".format(totalpacketsize*8/1000000))
	print("Current Bandwidth Usage: {} Mbps".format((totalpacketsize*8/1000000)/timeflag))

def ethernet_frame(data):
	#! signifies big endian to little endian. 6s = six bytes H= small unsigned int
	#beginning of ethernet frame is the preamble. allows device to sync receiver clocks
	print("14 DATA: ", data[:14])
	print()
	dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
	print("proto before: ", proto)
	print("proto after: ", socket.htons(proto))
	return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:] #grab payload
	#htons = host-to-network short.

#reformat mac address
def get_mac_addr(mac_bytes):
	bytes_str = map('{:02x}'.format, mac_bytes)
	mac = ':'.join(bytes_str).upper()
	return mac

#reformat ipv4 address
def get_ipv4_addr(ipv4_bytes):
	bytes_str = map(str, ipv4_bytes)
	ipv4 = '.'.join(bytes_str)
	return ipv4

#unpack ipv4 packet
def ipv4_packet(data):
	version_header_length = data[0]
	version = version_header_length >> 4
	header_length = version_header_length & 0xF

	#ttl = time to live
	ttl, proto, src, dest = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
	return version, header_length, ttl, proto, get_ipv4_addr(dest), get_ipv4_addr(src), data[header_length:]

#unpack icmp packet
def icmp_packet(data):
	icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
	return icmp_type, code, checksum, data[4:]

#unpack udp segment
def udp_segment(data):
	src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
	return src_port, dest_port, size, data[8:]

#unpack tcp segment
def tcp_segment(data):
	src_port, dest_port, seq, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
	offset = (offset_reserved_flags >> 12) * 4 
	flag_urg = (offset_reserved_flags & 32) >> 5
	flag_ack = (offset_reserved_flags & 16) >> 4
	flag_psh = (offset_reserved_flags & 8) >> 3
	flag_rst = (offset_reserved_flags & 4) >> 2
	flag_syn = (offset_reserved_flags & 2) >> 1
	flag_fin = offset_reserved_flags & 1
	return src_port, dest_port, seq, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]

if __name__ == "__main__":
	main()


"""
		print("An IP packet with size: ", totalLength)
		print("RAW DATA: ", data)
		print("\nPARSED DATA: ")
		print("Version:\t", str(version))
		print("Header Length:\t", str(header_length), " bytes")
		print("Type of Service:\n\t\t", getTOS(TOS))
		print("ID:\t\t", str(hex(ID)))
		print("Flags:\n\t\t", getFlags(flags))
		print("Fragment Offset:", str(fragmentOffset))
		print("TTL:\t\t", str(TTL))
		print("Protocol:\t", protocol)
		print("Checksum:\t", str(checksum))
		print("Source:\t\t", src)
		print("Destination:\t", dest)
		print("Payload:\n", data[20:]) 
---------------------------------------------
		dest_mac, src_mac, proto, payload = ethernet_frame(raw)
		# --- ethernet frame ---
		info += "Dest: {}, Src: {}, Proto type: {} \n". format(dest_mac, src_mac, proto)

		#protocol 8 for ipv4 - regular internet traffic
		#if proto == 8:
		version, header_length, ttl, proto_ipv4, dest, src, data = ipv4_packet(payload)
		info += "Version: " + str(version) + "\n"
		info += "Header Length: " + str(header_length) + "\n"
		info += "TTL: " + str(ttl) + "\n"
		info += "Protocol_ipv4: " + str(proto_ipv4) + "\n"
		info += "Dest: " + str(dest) + "\n"
		info += "Src: " + str(src) + "\n"

		info += "\n"
"""