
import socket
import sys
import time
from urlparse import urlparse
from random import randint
from struct import pack, unpack, calcsize

REMOTE_PORT = 80
LOCAL_PORT = 1234
LOCAL_HOST = randint(1001, 65535)
REMOTE_HOST = ''

# Flags
FLAGS = {'SYN': 2, 'ACK': 16, 'PSH_ACK': 24, 'FIN': 1, 'FIN_ACK': 17}

# Set up default value and sockets
MAX_SIZE = 65535
send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
tcp_sequence = 0
tcp_ack_sequence = 0
data_length = 0

# Make a TCP_Response object
class TCP_Response(object):
    def __init__(self, tcp_src, tcp_dst, tcp_sequence, tcp_ack_sequence, tcp_data_offset, tcp_check, tcp_flag,
                 tcp_data):
        self.tcp_src = tcp_src
        self.tcp_dst = tcp_dst
        self.tcp_sequence = tcp_sequence
        self.tcp_ack_sequence = tcp_ack_sequence
        self.tcp_data_offset = tcp_data_offset
        self.tcp_check = tcp_check
        self.tcp_flag = tcp_flag
        self.tcp_data = tcp_data


# Checksum functions needed for calculation checksum
def checksum(message):
    if len(message) % 2 == 1:
        message = message + pack('B', 0)
    _sum = 0
    for i in range(0, len(message), 2):
        w = ord(message[i]) + (ord(message[i + 1]) << 8)
        _sum += w
    _sum = (_sum >> 16) + (_sum & 0xffff)
    _sum += (_sum >> 16)
    _sum = ~_sum & 0xffff
    return _sum

# Extract source and destination address
def extract_addr(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    src_addr = s.getsockname()[0]
    dst_addr = socket.gethostbyname(host)
    return src_addr, dst_addr


# TCP Construction
def create_tcp_header(data, flags):
    global tcp_sequence, tcp_ack_sequence
    # Set TCP fields
    tcp_source = LOCAL_PORT
    tcp_dest = REMOTE_PORT
    tcp_seq = tcp_sequence
    tcp_ack_seq = tcp_ack_sequence
    tcp_doff = 5
    tcp_window = socket.htons(2048)
    tcp_check = 0
    tcp_urg_ptr = 0
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = flags
    # "Pack" TCP header
    tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                      tcp_window, tcp_check, tcp_urg_ptr)

    source_address = socket.inet_aton(LOCAL_HOST)
    dest_address = socket.inet_aton(REMOTE_HOST)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(data)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header + data

    tcp_check = checksum(psh)

    # "Pack" the tcp header again and fill the correct checksum
    tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                      tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)
    return tcp_header


# IP construction
def create_ip_header():
    # Set IP header fields
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0
    ip_id = randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(LOCAL_HOST)
    ip_daddr = socket.inet_aton(REMOTE_HOST)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # Pack IP header
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
                     ip_saddr, ip_daddr)
    return ip_header


# Extract host and path name from provided URL
def extract_url(url):
    try:
        parsed_url = urlparse(url)
    except:
        print "Invalid URL. Please try another URL!"
        sys.exit(1)
    host = parsed_url.netloc
    path = parsed_url.path

    return host, path

# Create packet to send
def create_packet(data, flags):
    tcp_header = create_tcp_header(data, flags)
    ip_header = create_ip_header()
    return ip_header + tcp_header + data

# Filter TCP Response
def filter_tcp_response(received_tcp_response):
    if not received_tcp_response:
        return False
    received_tcp_flags = received_tcp_response.tcp_flag
    received_tcp_ack_sequence = received_tcp_response.tcp_ack_sequence
    if (not (received_tcp_flags & FLAGS['ACK'])) or received_tcp_ack_sequence < tcp_sequence + 1:
        return False

    return True

# Get or unpack IP response
def get_ip_response(received_packet):
    # Get IP header list
    ip_header_buffer = received_packet[:20]
    ip_header_list = unpack('!BBHHHBBH4s4s', ip_header_buffer)
    ip_ver_ihl = ip_header_list[0]
    # Retrieve IP source and IP destination
    ip_src = socket.inet_ntoa(ip_header_list[-2])
    ip_dst = socket.inet_ntoa(ip_header_list[-1])
    # Calculate IP header size
    ip_header_size = calcsize('!BBHHHBBH4s4s')
    ip_ihl = ip_ver_ihl - (4 << 4)
    # Count for options
    if ip_ihl > 5:
        opts_size = (ip_ihl - 5) * 4
        ip_header_size += opts_size
    # Retrieve IP data
    ip_data = received_packet[ip_header_size:ip_header_list[2]]
    ip_header = received_packet[:ip_header_size]
    # Perform check sum
    ip_check_sum = checksum(ip_header)

    return ip_src, ip_dst, ip_data, ip_check_sum

# Get or unpack TCP response
def get_tcp_response(ip_data):
    # Get TCP header list
    tcp_header_size = calcsize('!HHLLBBHHH')
    tcp_header_buffer = ip_data[:tcp_header_size]
    tcp_header_list = unpack('!HHLLBBHHH', tcp_header_buffer)
    # Retrieve fields for TCP_Response object
    tcp_src = tcp_header_list[0]
    tcp_dst = tcp_header_list[1]
    tcp_seq = tcp_header_list[2]
    tcp_ack_seq = tcp_header_list[3]
    tcp_data_offset = tcp_header_list[4] >> 4
    # If contain some tcp options (5 is the minimum size of tcp header)
    if tcp_data_offset > 5:
        tcp_header_size += (tcp_data_offset - 5) * 4
    # Get tcp_check
    src_addr = socket.inet_aton(LOCAL_HOST)
    dest_addr = socket.inet_aton(REMOTE_HOST)
    placeholder = 0
    protocol_from_ip = socket.IPPROTO_TCP
    tcp_segment_length = len(ip_data)
    pseudo_header = pack('!4s4sBBH', src_addr, dest_addr, placeholder, protocol_from_ip, tcp_segment_length)
    pseudo_header = pseudo_header + ip_data
    tcp_check = checksum(pseudo_header)

    tcp_flag = tcp_header_list[5]
    tcp_data = ip_data[tcp_header_size:]
    # Return TCP_Response object
    return TCP_Response(tcp_src, tcp_dst, tcp_seq, tcp_ack_seq, tcp_data_offset, tcp_check, tcp_flag, tcp_data)


def is_valid_tcp_response(received_tcp_response):
    return not received_tcp_response.tcp_check and received_tcp_response.tcp_src == REMOTE_PORT and received_tcp_response.tcp_dst == LOCAL_PORT


def is_valid_ip_response(ip_src, ip_dst, ip_checksum):
    return not ip_checksum and ip_src == REMOTE_HOST and ip_dst == LOCAL_HOST


def receive_tcp():
    receive_socket.settimeout(60)
    try:
        while True:
            received_packet = receive_socket.recv(MAX_SIZE)
            ip_src, ip_dst, ip_data, ip_checksum = get_ip_response(received_packet)
            if is_valid_ip_response(ip_src, ip_dst, ip_checksum):
                received_tcp_response = get_tcp_response(ip_data)
                if is_valid_tcp_response(received_tcp_response):
                    return received_tcp_response
    except socket.timeout:
        print "Time out when getting packet"
        return None


def acked():
    global tcp_sequence, tcp_ack_sequence
    current_time = time.time()
    while time.time() - current_time < 10:
        received_tcp = receive_tcp()
        if filter_tcp_response(received_tcp):
            tcp_sequence = received_tcp.tcp_ack_sequence
            tcp_ack_sequence = received_tcp.tcp_sequence + 1
            return True

    return False


# TODO: https://accedian.com/blog/diagnose-tcp-connection-setup-issues/
# Three-way handshake
def established_connection():
    global tcp_sequence
    tcp_sequence = tcp_sequence = randint(0, (2 << 31) - 1)

    syn_packet = create_packet('', FLAGS['SYN'])
    send_socket.sendto(syn_packet, (REMOTE_HOST, REMOTE_PORT))

    if not acked():
        print "Cannot ACK when establishing connection!"
        return False

    ack_packet = create_packet('', FLAGS['ACK'])
    send_socket.sendto(ack_packet, (REMOTE_HOST, REMOTE_PORT))
    print "Done three-way handshake!"
    return True

#https://www.geeksforgeeks.org/tcp-connection-termination/
def acked_close():
    global tcp_sequence, tcp_ack_sequence

    fin_tcp = receive_tcp()
    fin_flag = fin_tcp.tcp_flag
    ack_tcp = receive_tcp()
    ack_tcp = ack_tcp.tcp_flag
    if fin_flag & FLAGS['FIN'] and ack_tcp & FLAGS['ACK']:
        return True

    return False


def closed_connection():
    #global send_socket, receive_socket
    fin_ack_packet = create_packet('', FLAGS['FIN_ACK'])
    send_socket.sendto(fin_ack_packet, (REMOTE_HOST, REMOTE_PORT))

    if acked():
        # tcp_response = receive_tcp()
        # flag = tcp_response.tcp_flag
        # if flag & FLAGS['FIN']:
        #     ack_packet = create_packet('', FLAGS['ACK'])
        #     send_socket.sendto(ack_packet, (REMOTE_HOST, REMOTE_PORT))
        #     send_socket.close()
        #     receive_socket.close()
        #     print "Connection is closed!"
        #     return True
        ack_packet = create_packet('', FLAGS['ACK'])
        send_socket.sendto(ack_packet, (REMOTE_HOST, REMOTE_PORT))
        send_socket.close()
        receive_socket.close()
        print "Connection closed!"
        return True

    print "Closing connection failed!"
    return False



# https://stackoverflow.com/questions/15182106/what-is-the-reason-and-how-to-avoid-the-fin-ack-rst-and-rst-ack
def received():
    global tcp_sequence, tcp_ack_sequence
    current_time = time.time()

    # Time out after 60s for getting packet
    while time.time() - current_time < 60:
        received_tcp = receive_tcp()
        if not received_tcp:
            print "Not received any packet"
            return False
        received_tcp_flags = received_tcp.tcp_flag
        received_tcp_ack_sequence = received_tcp.tcp_ack_sequence
        if received_tcp_flags & FLAGS['ACK'] and received_tcp_ack_sequence >= tcp_sequence + data_length:
            tcp_sequence = received_tcp.tcp_ack_sequence
            tcp_ack_sequence = received_tcp.tcp_sequence
            return True

    return False


def send(packet):
    current_time = time.time()
    send_socket.sendto(packet, (REMOTE_HOST, REMOTE_PORT))
    while not received():
        if time.time() - current_time > 180:
            print ("Time out when getting data")
            if not closed_connection():
                sys.exit(1)
            sys.exit(0)
        send_socket.sendto(packet, (REMOTE_HOST, REMOTE_PORT))
    print "Sent request"


def receive():
    global tcp_ack_sequence
    received_packets = {}

    while True:
        packet = receive_tcp()
        if not packet:
            print "Cannot connect to the server"
            if not closed_connection():
                sys.exit(1)
            sys.exit(1)
        packet_flags = packet.tcp_flag
        packet_tcp_sequence = packet.tcp_sequence
        packet_data = packet.tcp_data

        if packet_flags & FLAGS['ACK'] and packet_tcp_sequence not in received_packets:
            received_packets[packet_tcp_sequence] = packet_data
            tcp_ack_sequence = packet_tcp_sequence + len(packet_data)
            if packet_flags & FLAGS['FIN']:
                print "Finish receiving data!"
                return received_packets
                tcp_ack_sequence += 1
                if not closed_connection():
                    sys.exit(1)
                break
            else:
                ack_packet = create_packet('', FLAGS['ACK'])
                send_socket.sendto(ack_packet, (REMOTE_HOST, REMOTE_PORT))

    print "Received data"
    return received_packets


def is_valid(data):
    try:
        position = data.index("\r\n\r\n") + 4
    except:
        print "Invalid received data. Please try again!"
        return False, None

    header = data[:position]
    if "HTTP/1.1 200" not in header:
        print "Not return 200 status code"
        return False, None

    return True, data[position:]


def export_file(path, body):
    if not path:
        file_name = 'index.html'
    else:
        file_name = path.split('/')[-1]
    with open(file_name, "w+") as f:
        f.write(body)
    print "Successfully exported file:", file_name


def process_data(packets):
    packet_list = packets.items()
    packet_list.sort()
    data_list = [i[1] for i in packet_list]
    result = ''
    for data in data_list:
        result += data
    return result


def run(url):
    global LOCAL_HOST, REMOTE_HOST, data_length

    host, path = extract_url(url)
    src_addr, dst_addr = extract_addr(host)
    LOCAL_HOST = src_addr
    REMOTE_HOST = dst_addr

    if established_connection():
        request = "GET " + path + " HTTP/1.0\r\n" + "Host: " + host + "\r\n\r\n"
        data_length = len(request)
        packet = create_packet(request, FLAGS['PSH_ACK'])
        send(packet)
        packets = receive()
        data = process_data(packets)
        valid, body = is_valid(data)
        if not valid:
            sys.exit(1)
        export_file(path, body)
    else:
        print "Failed to establish connection!"
        send_socket.close()
        receive_socket.close()
        sys.exit(1)


def check_url(url):
    if "https://" in url:
        print ("Cannot handle https")
        sys.exit(1)

    if "http://" not in url:
        url = "http://" + url

    return url


if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit("Invalid number of arguments")
    url = check_url(sys.argv[1])
    run(url)
