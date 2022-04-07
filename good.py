
import socket
import sys
import time
from collections import namedtuple
from urlparse import urlparse
from random import randint
from struct import pack, unpack, calcsize



REMOTE_PORT = 80
LOCAL_PORT = randint(1001, 65535)
LOCAL_HOST = ''
REMOTE_HOST = ''

IPDatagram = namedtuple(
    'IPDatagram', 'ip_tlen ip_id ip_frag_off ip_saddr ip_daddr data ip_check')
TCPSeg = namedtuple(
    'TCPSeg', 'tcp_source tcp_dest tcp_seq tcp_ack_seq tcp_check data tcp_flags tcp_adwind')

# Flags
FLAGS = {'SYN': 0 + (1 << 1) + (0 << 2) + (0 << 3) + (0 << 4) + (0 << 5), 'ACK': 0 + (0 << 1) + (0 << 2) + (0 << 3) + (1 << 4) + (0 << 5), 'PSH_ACK': 0 + (0 << 1) + (0 << 2) + (1 << 3) + (1 << 4) + (0 << 5), 'FIN': 1 + (0 << 1) + (0 << 2) + (0 << 3) + (0 << 4) + (0 << 5), 'FIN_ACK': 1 + (0 << 1) + (0 << 2) + (0 << 3) + (1 << 4) + (0 << 5)}
# https://www.ibm.com/docs/en/zos/2.3.0?topic=concepts-introducing-tcpip-selecting-sockets
MAX_SIZE = 65535

send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
tcp_sequence = 0
tcp_ack_sequence = 0
send_buffer = ''

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



#https://www.delftstack.com/howto/python/get-ip-address-python/
def extract_addr(host):
    #src_addr = socket.gethostbyname(socket.gethostname())
    src_addr = '172.23.214.109' #TODO
    #print host
    dst_addr = socket.gethostbyname(host)
    return src_addr, dst_addr


# get from the tutorial
# TODO: REFACTOR TO AVOID PLAGIARISM
def create_tcp_header(src_addr, dst_addr, data, flags):

    tcp_source = LOCAL_PORT  # source port
    tcp_dest = REMOTE_PORT  # destination port
    tcp_seq = tcp_sequence
    tcp_ack_seq = tcp_ack_sequence
    tcp_doff = 5  # 4 bit field, size of tcp header, 5 * 4 = 20 bytes
    tcp_window = 2048  # maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = 0
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = flags

    tcp_header = pack('!HHLLBBHHH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window, tcp_check, tcp_urg_ptr)

    # pseudo header fields
    source_address = socket.inet_aton(LOCAL_HOST)
    dest_address = socket.inet_aton(REMOTE_HOST)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    # if len(data) % 2 != 0:
    #     data += ' '
    tcp_length = len(tcp_header) + len(data)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder,
                      protocol, tcp_length)
    psh = psh + tcp_header + data

    tcp_check = checksum(psh)
    tcp_header = pack('!HHLLBBHHH'[:-2], tcp_source, tcp_dest,
                             tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags, tcp_window) + \
                 pack('H', tcp_check) + pack('!H', tcp_urg_ptr)

    return tcp_header + data

# get from tutorial,
# TODO: REFACTOR TO AVOID PLAGIARISM
def create_ip_header(src_addr, dst_addr, data):
    # ip_ihl = 5
    # ip_ver = 4
    # ip_tos = 0
    # ip_tot_len = 20 + len(data)  # kernel will fill the correct total length
    # #ip_id = 54321  # Id of this packet
    # ip_id = randint(0, 65535)
    # ip_frag_off = 0
    # ip_ttl = 255
    # ip_proto = socket.IPPROTO_TCP
    # ip_check = 0  # kernel will fill the correct checksum
    # ip_saddr = socket.inet_aton(src_addr)  # Spoof the source ip address if you want to
    # ip_daddr = socket.inet_aton(dst_addr)
    #
    # ip_ihl_ver = (ip_ver << 4) + ip_ihl
    #
    # # the ! in the pack format string means network order
    # ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check,
    #                  ip_saddr, ip_daddr)
    ip_tos = 0
    ip_tot_len = 0
    ip_id = randint(0, 65535)
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(LOCAL_HOST)
    ip_daddr = socket.inet_aton(REMOTE_HOST)

    ip_ihl_ver = (4 << 4) + 5
    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len,
                            ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    ip_check = checksum(ip_header)

    ip_header = pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len,
                            ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

    return ip_header + data


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
    tcp_header = create_tcp_header(src_addr, dst_addr, data, flags)
    #unpack_tcp = get_tcp_response()
    ip_header = create_ip_header(src_addr, dst_addr, tcp_header)
    return ip_header


def filter_tcp_response(received_tcp_response):
    if not received_tcp_response:
        #print "empty"
        return False
    #print "response", received_tcp_response
    received_tcp_flags = received_tcp_response.tcp_flags
    #print "flag", received_tcp_flags
    received_tcp_ack_sequence = received_tcp_response.tcp_ack_seq
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
    # IP_header_buffer = received_packet[:20]
    # IP_header_list = unpack('!BBHHHBBH4s4s', IP_header_buffer)
    # ip_ver_ihl = IP_header_list[0]
    # # Retrieve IP source and IP destination
    # IP_src = socket.inet_ntoa(IP_header_list[-2])
    # IP_dst = socket.inet_ntoa(IP_header_list[-1])
    # IP_header_size = calcsize('!BBHHHBBH4s4s')
    # ip_ihl = ip_ver_ihl - (4 << 4)
    # if ip_ihl > 5:
    #     opts_size = (ip_ihl - 5) * 4
    #     IP_header_size += opts_size
    # # Calculate IP header size
    #
    #
    # # Retrieve IP data
    # IP_data = received_packet[IP_header_size:IP_header_list[2]]
    #
    # # Perform check sum
    # IP_header = received_packet[:IP_header_size]
    # IP_check_sum = checksum(IP_header)
    #
    #
    # return IP_src, IP_dst, IP_data, IP_check_sum

    hdr_fields = unpack('!BBHHHBBH4s4s', received_packet[:20])
    ip_header_size = calcsize('!BBHHHBBH4s4s')
    ip_ver_ihl = hdr_fields[0]
    ip_ihl = ip_ver_ihl - (4 << 4)

    if ip_ihl > 5:
        opts_size = (ip_ihl - 5) * 4
        ip_header_size += opts_size

    ip_headers = received_packet[:ip_header_size]

    data = received_packet[ip_header_size:hdr_fields[2]]
    ip_check = checksum(ip_headers)

    return IPDatagram(ip_daddr=socket.inet_ntoa(hdr_fields[-1]),
                      ip_saddr=socket.inet_ntoa(hdr_fields[-2]),
                      ip_frag_off=hdr_fields[4],
                      ip_id=hdr_fields[3],
                      ip_tlen=hdr_fields[2],
                      ip_check=ip_check, data=data)


#TODO
# https://www.quora.com/What-is-TCP-checksum
# https://www.oreilly.com/library/view/internet-core-protocols/1565925726/re69.html
# https://en.wikipedia.org/wiki/Transmission_Control_Protocol
def get_tcp_response(ip_data):
    # Get TCP header list
    # tcp_header_size = calcsize('!HHLLBBHHH')
    # tcp_header_buffer = ip_data[:tcp_header_size]
    # tcp_header_list = unpack('!HHLLBBHHH', tcp_header_buffer)
    # # Retrieve fields for TCP_Response object
    # tcp_src = tcp_header_list[0]
    # tcp_dst = tcp_header_list[1]
    # tcp_sequence = tcp_header_list[2]
    # tcp_ack_sequence = tcp_header_list[3]
    # tcp_data_offset = tcp_header_list[4] >> 4
    # # If contain some tcp options (5 is the minimum size of tcp header)
    # if tcp_data_offset > 5:
    #     tcp_header_size += (tcp_data_offset - 5) * 4
    # # Get tcp_check
    # src_addr = socket.inet_aton(LOCAL_HOST)
    # dest_addr = socket.inet_aton(REMOTE_HOST)
    # placeholder = 0
    # protocol_from_ip = socket.IPPROTO_TCP
    # tcp_segment_length = len(ip_data)
    # pseudo_header = pack('!4s4sBBH', src_addr, dest_addr, placeholder, protocol_from_ip, tcp_segment_length)
    # pseudo_header = pseudo_header + ip_data
    # tcp_check = checksum(pseudo_header)
    #
    # tcp_flag = tcp_header_list[5]
    # tcp_data = ip_data[tcp_header_size:]
    # # Return TCP_Response object
    # return TCP_Response(tcp_src, tcp_dst, tcp_sequence, tcp_ack_sequence, tcp_data_offset, tcp_check, tcp_flag, tcp_data)

    # hdr_fields = unpack('!BBHHHBBH4s4s', ip_data[:20])
    # ip_header_size = calcsize('!BBHHHBBH4s4s')
    # ip_ver_ihl = hdr_fields[0]
    # ip_ihl = ip_ver_ihl - (4 << 4)
    #
    # if ip_ihl > 5:
    #     opts_size = (ip_ihl - 5) * 4
    #     ip_header_size += opts_size
    #
    # ip_headers = ip_data[:ip_header_size]
    #
    # data = ip_data[ip_header_size:hdr_fields[2]]
    # ip_check = checksum(ip_headers)
    #
    # return IPDatagram(ip_daddr=socket.inet_ntoa(hdr_fields[-1]),
    #                   ip_saddr=socket.inet_ntoa(hdr_fields[-2]),
    #                   ip_frag_off=hdr_fields[4],
    #                   ip_id=hdr_fields[3],
    #                   ip_tlen=hdr_fields[2],
    #                   ip_check=ip_check, data=data)

    tcp_header_size = calcsize('!HHLLBBHHH')
    hdr_fields = unpack('!HHLLBBHHH', ip_data[:tcp_header_size])
    tcp_source = hdr_fields[0]
    tcp_dest = hdr_fields[1]
    tcp_seq = hdr_fields[2]
    tcp_ack_seq = hdr_fields[3]
    tcp_doff_resvd = hdr_fields[4]
    tcp_doff = tcp_doff_resvd >> 4  # get the data offset
    tcp_adwind = hdr_fields[6]
    tcp_urg_ptr = hdr_fields[7]
    # parse TCP flags
    tcp_flags = hdr_fields[5]
    # process the TCP options if there are
    # currently just skip it
    if tcp_doff > 5:
        opts_size = (tcp_doff - 5) * 4
        tcp_header_size += opts_size
    # get the TCP data
    data = ip_data[tcp_header_size:]
    # compute the checksum of the recv packet with psh
    tcp_check = _tcp_check(ip_data)
    # tcp_check = 0
    return TCPSeg(tcp_seq=tcp_seq,
                  tcp_source=tcp_source,
                  tcp_dest=tcp_dest,
                  tcp_ack_seq=tcp_ack_seq,
                  tcp_adwind=tcp_adwind,
                  tcp_flags=tcp_flags, tcp_check=tcp_check, data=ip_data[tcp_header_size:])


def _tcp_check(payload):
    # pseudo header fields
    source_address = socket.inet_aton(LOCAL_HOST)
    dest_address = socket.inet_aton(REMOTE_HOST)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(payload)

    psh = pack('!4s4sBBH', source_address, dest_address,
                      placeholder, protocol, tcp_length)
    psh = psh + payload

    return checksum(psh)



def is_valid_tcp_response(received_tcp_response):
    return not received_tcp_response.tcp_check and received_tcp_response.tcp_src == REMOTE_PORT and received_tcp_response.tcp_dst == LOCAL_PORT


def is_valid_ip_response(ip_src, ip_dst, ip_checksum):
    return not ip_checksum and ip_src == REMOTE_HOST and ip_dst == LOCAL_HOST


def receive_tcp():
    receive_socket.settimeout(60)
    #print "start receive"
    #print tcp_sequence
    try:
        while True:
            # print "in loop"
            # received_packet = receive_socket.recv(MAX_SIZE)
            # print "received packet"
            # ip_src, ip_dst, ip_data, ip_checksum = get_ip_response(received_packet)
            # #print ip_src, ip_dst, ip_data, ip_checksum
            # if is_valid_ip_response(ip_src, ip_dst, ip_checksum):
            #     print "valid ip"
            #     received_tcp_response = get_tcp_response(ip_data)
            #     if is_valid_tcp_response(received_tcp_response):
            #         #print "valid tcp"
            #         print "receieve tcp!!"
            #         return received_tcp_response

            data = receive_socket.recv(MAX_SIZE)
            ip_datagram = get_ip_response(data)
            if ip_datagram.ip_daddr != LOCAL_HOST or ip_datagram.ip_check != 0 or ip_datagram.ip_saddr != REMOTE_HOST:
                continue

            tcp_seg = get_tcp_response(ip_datagram.data)
            #print tcp_seg.data
            if tcp_seg.tcp_source != REMOTE_PORT or tcp_seg.tcp_dest != LOCAL_PORT or tcp_seg.tcp_check != 0:
                continue
            return tcp_seg
    except socket.timeout:
        print "Time out when getting packet"
        return None

#nho sua
def acked():
    global tcp_sequence, tcp_ack_sequence
    start_time = time.time()
    while time.time() - start_time < 60:
        tcp_seg = receive_tcp()
        if not tcp_seg:
            break
        if tcp_seg.tcp_flags & FLAGS['ACK'] and tcp_seg.tcp_ack_seq >= tcp_sequence + 1:
            tcp_sequence = tcp_seg.tcp_ack_seq
            tcp_ack_sequence = tcp_seg.tcp_seq + 1
            return True

    return False

# TODO: https://accedian.com/blog/diagnose-tcp-connection-setup-issues/
#Three-way handshake
def established_connection(src_addr, dst_addr):
    #print REMOTE_HOST, REMOTE_PORT
    global tcp_sequence
    tcp_sequence = randint(0, (2 << 31) - 1)
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
        flag = tcp_response.tcp_flags
        if flag & FLAGS['FIN']:
            send_socket.sendto(ack_packet, (REMOTE_HOST, REMOTE_PORT))
            send_socket.close()
            receive_socket.close()
            print "Connection is closed"
            return True

    print "Closing connection failed!"
    return False

# fuck
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
        received_tcp_flags = received_tcp.tcp_flags
        received_tcp_ack_sequence = received_tcp.tcp_ack_seq
        if received_tcp_flags & FLAGS['ACK'] and received_tcp_ack_sequence >= tcp_sequence + len(send_buffer):
            tcp_sequence = received_tcp.tcp_ack_seq
            tcp_ack_sequence = received_tcp.tcp_seq
            return True

    return False


def send(packet):
    global send_buffer
    current_time = time.time()
    #print REMOTE_HOST, REMOTE_PORT
    send_socket.sendto(packet, (REMOTE_HOST, REMOTE_PORT))
    while not received():
        if time.time() - current_time > 180:
            print ("Time out when getting data")
            if not closed_connection():
                sys.exit(1)
            sys.exit(0)
        send_socket.sendto(packet, (REMOTE_HOST, REMOTE_PORT))
    send_buffer = ''
    print "Sent data"


def receive():
    global tcp_ack_sequence
    received_packets = {}

    while True:
        packet = receive_tcp()
        if not packet:
            print "Cannot connect to the server"
            # if not closed_connection():
            #     sys.exit(1)
            sys.exit(1)
        #rint "receiving packets ..."
        #print "here"
        packet_flags = packet.tcp_flags
        packet_tcp_sequence = packet.tcp_seq
        packet_data = packet.data
        #print "packet_flags ", packet_flags
        #print "sequence ", packet_tcp_sequence
        #print "data: ", packet_data

        if packet_flags & FLAGS['ACK'] and packet_tcp_sequence not in received_packets:
            received_packets[packet_tcp_sequence] = packet_data
            tcp_ack_sequence = packet_tcp_sequence + len(packet_data)
            #print "putting data in ..."
            #print received_packets
            if packet_flags & FLAGS['FIN']:
                print "Finish!"
                return received_packets
                tcp_ack_sequence += 1
                if not closed_connection():
                    sys.exit(1)
                break
            else:
                ack_packet = create_packet(LOCAL_HOST, REMOTE_HOST, '', FLAGS['ACK'])
                send_socket.sendto(ack_packet, (REMOTE_HOST, REMOTE_PORT))
                #print "send back ack ..."

    print "Received data"
    return received_packets


def is_valid(data):
    print data
    try:
        position = data.index("\r\n\r\n") + 4
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
    packet_list = packets.items()
    packet_list.sort()
    data_list = [i[1] for i in packet_list]
    result = ''
    for data in data_list:
        result += data
    return result


def run(url):
    global LOCAL_HOST, REMOTE_HOST, buffer_length, send_buffer

    host, path = extract_url(url)
    src_addr, dst_addr = extract_addr(host)
    LOCAL_HOST = src_addr
    REMOTE_HOST = dst_addr

    if established_connection(LOCAL_HOST, REMOTE_HOST):
        request = "GET " + path + " HTTP/1.0\r\n" + "Host: " + host + "\r\n\r\n"
        buffer_length = len(request)
        #print "request", request
        send_buffer = request
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
        #send_socket.close()
        #receive_socket.close()
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






