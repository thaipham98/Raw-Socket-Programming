import socket
import sys
import time
from random import randint
from struct import pack, unpack, calcsize



PORT = 80
LOCAL_HOST = ''
REMOTE_HOST = ''

# Flags
FLAGS = {'SYN': 2, 'ACK': 16, 'PSH_ACK': 24, 'FIN': 1, 'FIN_ACK': 17}
MAX_SIZE = 65535

send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
tcp_sequence = 0
tcp_ack_sequence = 0


class TCP_Response(object):
    # tcp_src = ''
    # tcp_dst = ''
    # tcp_sequence = 0
    # tcp_ack_sequence = 0
    # tcp_check = 0
    # tcp_flag =
    # tcp_data =

    def __init__(self, tcp_src, tcp_dst, tcp_sequence, tcp_ack_sequence, tcp_doff, tcp_check, tcp_flag, tcp_data):
        self.tcp_src = tcp_src
        self.tcp_dst = tcp_dst
        self.tcp_sequence = tcp_sequence
        self.tcp_ack_sequence = tcp_ack_sequence
        self.tcp_doff = tcp_doff
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
# TODO: REFACTOR TO AVOID PLAGIARISM
def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)

    # complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

#TODO
def extract_addr(host):
    #return src_addr, dst_addr
    pass


# get from the tutorial
# TODO: REFACTOR TO AVOID PLAGIARISM
def create_tcp_header(src_addr, dst_addr, data, flags):
    tcp_source = 1234  # source port
    tcp_dest = PORT  # destination port
    tcp_seq = 454
    tcp_ack_seq = 0
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




#TODO
def extract_url(url):
    pass




def create_packet(src_addr, dst_addr, data, flags):
    ip_header = create_ip_header(src_addr, dst_addr)
    tcp_header = create_tcp_header(src_addr, dst_addr, data, flags)

    return ip_header + tcp_header + data

#TODO
def filter_TCP_response(received_tcp_response):
    if not received_tcp_response:
        return False
    return True
    #received_tcp_response


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
def get_tcp_response(ip_data):
    '''
    self.tcp_src = tcp_src
    self.tcp_dst = tcp_dst
    self.tcp_sequence = tcp_sequence
    self.tcp_ack_sequence = tcp_ack_sequence
    self.tcp_doff = tcp_doff
    self.tcp_check = tcp_check
    self.tcp_flag = tcp_flag
    self.tcp_data = tcp_data
    '''
    # Get TCP header list
    tcp_header_size = calcsize('!HHLLBBH')
    tcp_header_buffer = ip_data[:tcp_header_size]
    tcp_header_list = unpack('!HHLLBBH', tcp_header_buffer)

    # Retrieve fields for TCP_Response object
    tcp_src = tcp_header_list[0]
    tcp_dst = tcp_header_list[1]
    tcp_sequence = tcp_header_list[2]
    tcp_ack_sequence = tcp_header_list[3]
    tcp_doff = tcp_header_list[4] >> 4
    if tcp_doff > 5:
        option_size = (tcp_doff - 5) * 4
        tcp_header_size += option_size

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
    return TCP_Response(tcp_src, tcp_dst, tcp_sequence, tcp_ack_sequence, tcp_flag, tcp_check, tcp_data)






#TODO
def is_valid_tcp_response(received_tcp_response):
    return not received_tcp_response.


def is_valid_ip_response(ip_src, ip_dst, ip_checksum):
    return not ip_checksum and ip_src == REMOTE_HOST and ip_dst == LOCAL_HOST


def receive():
    receive_socket.settimeout(60)
    try:
        while True:
            received_packet = receive_socket.recv(MAX_SIZE)
            # TODO B
            ip_src, ip_dst, ip_data, ip_checksum = get_ip_response(received_packet)
            if is_valid_ip_response(ip_src, ip_dst, ip_checksum):
                #TODO B
                received_tcp_response = get_tcp_response(ip_data)
                if is_valid_tcp_response(received_tcp_response):
                    return received_tcp_response
    except socket.timeout:
        print "Time out when getting packet"
        return None




def acked():
    global tcp_sequence, tcp_ack_sequence
    current_time = time.time()
    while time.time() - current_time < 60:
        received_tcp = receive()
        if filter_TCP_response(received_tcp):
            tcp_sequence = received_tcp.tcp_ack_sequence
            tcp_ack_sequence = received_tcp.tcp_sequence + 1
            return True

    return False


def establish_connection(src_addr, dst_addr):
    global tcp_sequence
    syn_packet = create_packet(src_addr, dst_addr, '', FLAGS['SYN'])
    tcp_sequence = randint(0, int("inf"))
    send_socket.sendto(syn_packet, (REMOTE_HOST, PORT))

    if not acked():
        print "Failed to establish connection!"
        sys.exit(1)

    ack_packet = create_packet(src_addr, dst_addr, FLAGS['ACK'])
    send_socket.sendto(ack_packet, (REMOTE_HOST, PORT))

#TODO
def run(url):

    path, host = extract_url(url)
    HOST = host
    request = "GET " + path + " HTTP/1.1\r\n" + "Host: " + host + "\r\n\r\n"

    src_addr, dst_addr = extract_addr(HOST)

    establish_connection(src_addr, dst_addr)








if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit("Invalid number of arguments")
    url = sys.argv[1]
    run(url)
    #print(url)






