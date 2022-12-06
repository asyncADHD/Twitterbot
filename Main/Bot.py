import socket
import struct

# Create a raw socket and bind it to the public interface
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
s.bind(('', 0))

# Include the IP headers in the captured packets
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Receive all incoming packets
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Open a file for writing the URLs
f = open('urls.txt', 'w')

# Process each incoming packet
while True:
    # Read the packet data
    packet = s.recvfrom(65565)

    # Parse the IP header
    ip_header = packet[0][0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

    # Get the protocol (TCP or UDP) and the destination IP address
    protocol = iph[6]
    dest_ip = socket.inet_ntoa(iph[9])

    # If the protocol is TCP
    if protocol == 6:
        # Parse the TCP header
        tcp_header = packet[0][20:40]
        tcph = struct.unpack('!HHLLBBHHH', tcp_header)

        # Get the destination port
        dest_port = tcph[1]

        # If the destination port is 80 (HTTP) or 443 (HTTPS), process the packet
        if dest_port == 80 or dest_port == 443:
            # Calculate the total length of the packet
            total_length = iph[2]
            header_length = iph[0] & 0xF
            header_size = header_length * 4
            data_size = total_length - header_size

            # Get the data (URL) from the packet
            data = packet[0][header_size:header_size + data_size]

            # Decode the URL and write it to the file
            url = data.decode('utf-8')
            f.write(url + '\n')

# Close the file
f.close()

# Stop receiving packets
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
