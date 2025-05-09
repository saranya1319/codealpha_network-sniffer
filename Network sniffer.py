import socket
import struct

def main():
    # Create a raw socket and bind it to the public interface
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Use your own IP address here
    host = socket.gethostbyname(socket.gethostname())
    sniffer.bind((host, 0))

    # Include the IP headers in the capture
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Enable promiscuous mode on Windows
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"[*] Sniffing on {host}...\n")

    try:
        while True:
            # Receive a packet
            raw_packet = sniffer.recvfrom(65565)[0]

            # Unpack the IP header (first 20 bytes)
            ip_header = raw_packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            protocol = iph[6]
            src_addr = socket.inet_ntoa(iph[8])
            dst_addr = socket.inet_ntoa(iph[9])

            print(f'Protocol: {protocol} | Source: {src_addr} -> Destination: {dst_addr}')

    except KeyboardInterrupt:
        print('\n[!] Stopping sniffer.')
        # Turn off promiscuous mode
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main()
