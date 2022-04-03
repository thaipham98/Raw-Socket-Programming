
import socket
import sys
import time
from urlparse import urlparse
from random import randint
from struct import pack, unpack, calcsize



REMOTE_PORT = 80
LOCAL_PORT = 1234
LOCAL_HOST = ''
REMOTE_HOST = ''

# Flags
FLAGS = {'SYN': 2, 'ACK': 16, 'PSH_ACK': 24, 'FIN': 1, 'FIN_ACK': 17}
# https://www.ibm.com/docs/en/zos/2.3.0?topic=concepts-introducing-tcpip-selecting-sockets
MAX_SIZE = 65535

send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
tcp_sequence = 0
tcp_ack_sequence = 0
buffer_length = 0

# TODO: Close connection
# https://cs.stackexchange.com/questions/76393/tcp-connection-termination-fin-fin-ack-ack
# https://accedian.com/blog/close-tcp-sessions-diagnose-disconnections/#:~:text=The%20standard%20way%20to%20close,response%20from%20the%20other%20party.&text=B%20can%20now%20send%20a,acknowledgement%20(Last%20Ack%20wait).
# https://wiki.wireshark.org/TCP-4-times-close.md

class TCP_Response(object):
    # tcp_src = ''
    # tcp_dst = ''
    # tcp_sequence = 0
    # tcp_ack_sequence = 0
    # tcp_check = 0
    # tcp_flag =
    # tcp_data =

    def __init__(self, tcp_src, tcp_dst, tcp_sequence, tcp_ack_sequence, tcp_data_offset, tcp_check, tcp_flag, tcp_data):
        self.tcp_src = tcp_src
        self.tcp_dst = tcp_dst
        self.tcp_sequence = tcp_sequence
        self.tcp_ack_sequence = tcp_ack_sequence
        self.tcp_data_offset = tcp_data_offset
        self.tcp_check = tcp_check
        self.tcp_flag = tcp_flag
        self.tcp_data = tcp_data


# class IP_Response(object):
#     ip_src = ''
#     ip_dst = ''
#     ip_check = 0
#
#     def __init__(self, ip_src, ip_dst, ip_check):
#         self.ip_src = ip_src
#         self.ip_dst = ip_dst
#         self.ip_check = ip_check

# checksum functions needed for calculation checksum
# TODO: REFACTOR TO AVOID PLAGIARISM? KB DC CHUA
def checksum(message):
    _sum = 0
    for i in range(0, len(message), 2):
        w = ord(message[i]) + (ord(message[i + 1]) << 8)
        _sum += w
    _sum = (_sum >> 16) + (_sum & 0xffff)
    _sum += (_sum >> 16)
    _sum = ~_sum & 0xffff
    return _sum

#https://www.delftstack.com/howto/python/get-ip-address-python/
def extract_addr(host):
    #src_addr = socket.gethostbyname(socket.gethostname())
    src_addr = '172.27.120.95' #TODO
    #print host
    dst_addr = socket.gethostbyname(host)
    return src_addr, dst_addr


# get from the tutorial
# TODO: REFACTOR TO AVOID PLAGIARISM
def create_tcp_header(src_addr, dst_addr, data, flags):
    global tcp_sequence, tcp_ack_sequence
    tcp_source = LOCAL_PORT  # source port
    tcp_dest = REMOTE_PORT  # destination port
    tcp_seq = tcp_sequence
    tcp_ack_seq = tcp_ack_sequence
    #print "tcp_ack_seq in tcp", tcp_ack_sequence
    tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
    tcp_window = socket.htons(5840)  # maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = flags

    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window,
                      tcp_check, tcp_urg_ptr)
    source_address = socket.inet_aton(src_addr)
    dest_address = socket.inet_aton(dst_addr)
    placeholder = 0
    protocol = socket.IPPROTO_TCP

    # if len(data) % 2 != 0:
    #     data += ' '

    tcp_length = len(tcp_header) + len(data)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header + data

    tcp_check = checksum(psh)
    # print tcp_checksum

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                      tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)
    return tcp_header

# get from tutorial,
# TODO: REFACTOR TO AVOID PLAGIARISM
def create_ip_header(src_addr, dst_addr):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = 54321  # Id of this packet
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0  # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton(src_addr)  # Spoof the source ip address if you want to
    ip_daddr = socket.inet_aton(dst_addr)

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
                     ip_saddr, ip_daddr)

    return ip_header


def extract_url(url):
    try:
        parsed_url = urlparse(url)
    except:
        print "Invalid URL. Please try another URL!"
        sys.exit(1)
    host = parsed_url.netloc
    path = parsed_url.path

    return host, path


def create_packet(src_addr, dst_addr, data, flags):
    ip_header = create_ip_header(src_addr, dst_addr)
    tcp_header = create_tcp_header(src_addr, dst_addr, data, flags)

    return ip_header + tcp_header + data


def filter_tcp_response(received_tcp_response):
    if not received_tcp_response:
        #print "empty"
        return False
    #print "response", received_tcp_response
    received_tcp_flags = received_tcp_response.tcp_flag
    #print "flag", received_tcp_flags
    received_tcp_ack_sequence = received_tcp_response.tcp_ack_sequence
    #print "ack_sequence", received_tcp_ack_sequence
    #print "tcp_sequence", tcp_sequence
    if (not (received_tcp_flags & FLAGS['ACK'])) or received_tcp_ack_sequence < tcp_sequence + 1:
        #print "not tcp acked"
        return False

    #sys.exit(1)
    return True


#TODO: done
# https://www.cs.miami.edu/home/burt/learning/Csc524.092/notes/ip_example.html
def get_ip_response(received_packet):
    # Get IP header list
    IP_header_buffer = received_packet[:20]
    IP_header_list = unpack('!BBHHHBBH4s4s', IP_header_buffer)

    # Retrieve IP source and IP destination
    IP_src = socket.inet_ntoa(IP_header_list[-2])
    IP_dst = socket.inet_ntoa(IP_header_list[-1])

    # Calculate IP header size
    IP_header_size = calcsize('!BBHHHBBH4s4s')

    # Retrieve IP data
    IP_data = received_packet[IP_header_size:IP_header_list[2]]

    # Perform check sum
    IP_header = received_packet[:IP_header_size]
    IP_check_sum = checksum(IP_header)


    return IP_src, IP_dst, IP_data, IP_check_sum



#TODO
# https://www.quora.com/What-is-TCP-checksum
# https://www.oreilly.com/library/view/internet-core-protocols/1565925726/re69.html
# https://en.wikipedia.org/wiki/Transmission_Control_Protocol
def get_tcp_response(ip_data):
    # Get TCP header list
    tcp_header_size = calcsize('!HHLLBBH')
    tcp_header_buffer = ip_data[:tcp_header_size]
    tcp_header_list = unpack('!HHLLBBH', tcp_header_buffer)
    # Retrieve fields for TCP_Response object
    tcp_src = tcp_header_list[0]
    tcp_dst = tcp_header_list[1]
    tcp_sequence = tcp_header_list[2]
    tcp_ack_sequence = tcp_header_list[3]
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
    return TCP_Response(tcp_src, tcp_dst, tcp_sequence, tcp_ack_sequence, tcp_data_offset, tcp_check, tcp_flag, tcp_data)



def is_valid_tcp_response(received_tcp_response):
    return not received_tcp_response.tcp_check and received_tcp_response.tcp_src == REMOTE_PORT and received_tcp_response.tcp_dst == LOCAL_PORT


def is_valid_ip_response(ip_src, ip_dst, ip_checksum):
    return not ip_checksum and ip_src == REMOTE_HOST and ip_dst == LOCAL_HOST


def receive_tcp():
    receive_socket.settimeout(5)
    #print "start receive"
    #print tcp_sequence
    try:
        while True:
            received_packet = receive_socket.recv(MAX_SIZE)
            #print "received packet"
            ip_src, ip_dst, ip_data, ip_checksum = get_ip_response(received_packet)
            #print ip_src, ip_dst, ip_data, ip_checksum
            if is_valid_ip_response(ip_src, ip_dst, ip_checksum):
                #print "valid ip"
                received_tcp_response = get_tcp_response(ip_data)
                if is_valid_tcp_response(received_tcp_response):
                    #print "valid tcp"
                    return received_tcp_response
    except socket.timeout:
        print "Time out when getting packet"
        return None


def acked():
    global tcp_sequence, tcp_ack_sequence
    current_time = time.time()
    #print tcp_sequence
    while time.time() - current_time < 10:
        received_tcp = receive_tcp()
        if filter_tcp_response(received_tcp):
            #print "acked"
            tcp_sequence = received_tcp.tcp_ack_sequence
            tcp_ack_sequence = received_tcp.tcp_sequence + 1
            return True

    return False

# TODO: https://accedian.com/blog/diagnose-tcp-connection-setup-issues/
#Three-way handshake
def established_connection(src_addr, dst_addr):
    #print REMOTE_HOST, REMOTE_PORT
    global tcp_sequence
    tcp_sequence = randint(0, MAX_SIZE)
    syn_packet = create_packet(src_addr, dst_addr, '', FLAGS['SYN'])
    #print syn_packet
    send_socket.sendto(syn_packet, (REMOTE_HOST, REMOTE_PORT))

    if not acked():
        print "Cannot ACK when establishing connection!"
        return False


    ack_packet = create_packet(src_addr, dst_addr, '', FLAGS['ACK'])
    send_socket.sendto(ack_packet, (REMOTE_HOST, REMOTE_PORT))
    print "Done 3way handshake!"
    return True

def closed_connection():
    fin_ack_packet = create_packet(LOCAL_HOST, REMOTE_HOST, '', FLAGS['FIN_ACK'])
    ack_packet = create_packet(LOCAL_HOST, REMOTE_HOST, '', FLAGS['ACK'])

    current_time = time.time()

    # Time out after 60s for closing connection
    while time.time() - current_time < 30:
        send_socket.sendto(fin_ack_packet, (REMOTE_HOST, REMOTE_PORT))
        tcp_response = receive_tcp()
        flag = tcp_response.tcp_flag
        if flag & FLAGS['FIN']:
            send_socket.sendto(ack_packet, (REMOTE_HOST, REMOTE_PORT))
            send_socket.close()
            receive_socket.close()
            print "Connection is closed"
            return True

    print "Closing connection failed!"
    return False


# https://stackoverflow.com/questions/15182106/what-is-the-reason-and-how-to-avoid-the-fin-ack-rst-and-rst-ack
def received():
    global tcp_sequence, tcp_ack_sequence, buffer_length
    current_time = time.time()

    #Time out after 60s for getting packet
    while time.time() - current_time < 60:
        received_tcp = receive_tcp()
        if not received_tcp:
            print "Not received any packet"
            return False
        received_tcp_flags = received_tcp.tcp_flag
        received_tcp_ack_sequence = received_tcp.tcp_ack_sequence
        if received_tcp_flags & FLAGS['ACK'] and received_tcp_ack_sequence >= tcp_sequence + buffer_length:
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
    print "Received data"


def receive():
    global tcp_ack_sequence
    received_packets = {}

    while True:
        packet = receive_tcp()
        if not packet:
            print "Cannot connect to the server"
            if not closed_connection():
                sys.exit(1)
            sys.exit(0)

        packet_flags = packet.tcp_flag
        packet_tcp_sequence = packet.tcp_sequence
        packet_data = packet.tcp_data

        if packet_flags & FLAGS['ACK']:
            received_packets[packet_tcp_sequence] = packet_data
            tcp_ack_sequence += packet_tcp_sequence + len(packet_data)

        elif packet_flags & FLAGS['FIN']:
            tcp_ack_sequence += 1
            if not closed_connection():
                sys.exit(1)
            break
        else:
            ack_packet = create_packet(LOCAL_HOST, REMOTE_HOST, FLAGS['ACK'])
            send_socket.sendto(ack_packet, (REMOTE_HOST, REMOTE_PORT))

    return received_packets


def is_valid(data):
    try:
        position = data.index("\r\n\r\n")
    except:
        print "Invalid received"
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
        print "Successfully exported file!"


def process_data(packets):
    data_list = [i[1] for i in packets.items().sort()]
    result = ''
    for data in data_list:
        result += data
    return result


def run(url):
    global LOCAL_HOST, REMOTE_HOST, buffer_length

    host, path = extract_url(url)
    src_addr, dst_addr = extract_addr(host)
    LOCAL_HOST = src_addr
    REMOTE_HOST = dst_addr

    if established_connection(LOCAL_HOST, REMOTE_HOST):
        request = "GET " + path + " HTTP/1.1\r\n" + "Host: " + host + "\r\n\r\n"
        buffer_length = len(request)
        packet = create_packet(LOCAL_HOST, REMOTE_HOST, request, FLAGS['PSH_ACK'])
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
    #print url
    run(url)






