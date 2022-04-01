import socket
import sys
from struct import pack



PORT = 80
HOST = ''

# Flags
FLAGS = {'SYN': 2, 'SYN_ACK': 18, 'ACK': 16, 'PSH_ACK': 24, 'FIN': 1, 'FIN_ACK': 17}

send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
receive_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# checksum functions needed for calculation checksum
def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i + 1]) << 8)
        s = s + w

    s = (s >> 16) + (s & 0xffff);
    s = s + (s >> 16);

    # complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

def extract_addr(host):
    #return src_addr, dst_addr
    pass


# get from the tutorial
def create_tcp_header(src_addr, dst_addr, flags):
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
    tcp_length = len(tcp_header)

    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header

    tcp_check = checksum(psh)
    # print tcp_checksum

    # make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
    tcp_header = pack('!HHLLBBH', tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,
                      tcp_window) + pack('H', tcp_check) + pack('!H', tcp_urg_ptr)
    return tcp_header

# get from tutorial
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
    pass



def create_tcp_layer():
    pass


def process_data(browser_data):
    pass


def establish_tcp_connection(tcp_layer, host, PORT):
    pass


def creat_packet(ip_header, tcp_header, data=''):
    return ip_header + tcp_header + data


def three_way_handshake(packet):

    pass


def establish_connection(src_addr, dst_addr):
    ip_header = create_ip_header(src_addr, dst_addr)
    tcp_header = create_tcp_header(src_addr, dst_addr, FLAGS['SYN'])
    packet = creat_packet(ip_header, tcp_header)




def run(url):

    path, host = extract_url(url)
    HOST = host
    request = "GET " + path + " HTTP/1.1\r\n" + "Host: " + host + "\r\n\r\n"



    src_addr, dst_addr = extract_addr(HOST)



    establish_connection(src_addr, dst_addr)
    three_way_handshake(packet)







if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit("Invalid number of arguments")
    url = sys.argv[1]
    run(url)
    #print(url)






