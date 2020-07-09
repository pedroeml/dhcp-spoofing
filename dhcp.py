import select, socket, sys, queue
import struct

ETH_P_ALL = 0x0003
ETH_LENGTH = 14
DHCP_RELEASE = 7
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5
MY_IP_ADDR = '10.0.0.20'
IP_POOL = [{'ip': '10.0.0.%d' % v, 'mac': None } for v in range(100, 127)]


def find_free_ip():
    for ip in IP_POOL:
        if ip['mac'] is None:
            return ip

    return None


def find_ip(mac):
    for ip in IP_POOL:
        if ip['mac'] == mac:
            return ip

    return None
            

def release_ip(mac):
    for ip in IP_POOL:
        if ip['mac'] == mac:
            ip['mac'] = None
            print('Released IP (%s) from MAC (%s)' % (ip['ip'], bytes_to_mac(mac)))
            return True

    return False


def bytes_to_mac(bytesmac):
    return ':'.join('{:02x}'.format(x) for x in bytesmac)


def checksum(msg):
    s = 0
    msg = (msg + b'\x00') if len(msg)%2 else msg
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i+1] << 8)
        s = s + w
        s = (s & 0xffff) + (s >> 16)
    s = ~s & 0xffff
    return socket.ntohs(s)


def create_socket(interface_name):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    s.bind((interface_name, 0))
    mac_addr = s.getsockname()[-1]
    print(interface_name + ' MAC address:' + bytes_to_mac(mac_addr))

    return (s, mac_addr)


def pack_ip_header(packet, s_ip_addr, d_ip_addr):
    iph = struct.unpack('!BBHHHBBH4s4s', packet[ETH_LENGTH:20+ETH_LENGTH])
    # Header IP
    ip_ver = 4
    ip_ihl = 5
    ip_tos = iph[1]
    ip_tot_len = iph[2]
    ip_id = iph[3]
    ip_frag_off = iph[4]
    ip_ttl = iph[5]
    ip_proto = iph[6]
    ip_check = 0
    ip_saddr = socket.inet_aton(s_ip_addr) if s_ip_addr is not None else iph[-2]
    ip_daddr = socket.inet_aton(d_ip_addr) if d_ip_addr is not None else iph[-1]

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
        ip_proto, ip_check, ip_saddr, ip_daddr)

    ip_check = checksum(ip_header)

    ip_header = struct.pack('!BBHHHBBH4s4s', ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl,
        ip_proto, ip_check, ip_saddr, ip_daddr)

    return (ip_header, ip_proto, ip_saddr, ip_daddr)


def unpack_bootp(packet):
    bootp_header = struct.unpack('!BBBB4sHH4s4s4s4s6s10s192s4sBBBBB4sBB4sBB4sBB4sBB9sBB4sB15s', packet[28+ETH_LENGTH:])

    xid = bootp_header[4]
    chaddr = bootp_header[11]
    mtype_option = bootp_header[17]

    return (xid, chaddr, mtype_option)

def pack_bootp(discover_transaction_id, client_ip_addr, client_mac_addr, is_offer=True):
    op = 2
    htype = 1
    hlen = 6
    hops = 0
    xid = discover_transaction_id
    secs = 0
    flags = 0
    ciaddr = socket.inet_aton('0.0.0.0')
    yiaddr = client_ip_addr
    siaddr = socket.inet_aton(MY_IP_ADDR)
    giaddr = socket.inet_aton('0.0.0.0')
    chaddr = client_mac_addr
    chapadding = bytes.fromhex(''.join(['00' for i in range(0, 10)]))
    padding = bytes.fromhex(''.join(['00' for i in range(0, 192)]))
    magic_cookie = b'\x63\x82\x53\x63'
    mtype = 53
    mtype_len = 1
    mtype_option = DHCP_OFFER if is_offer else DHCP_ACK
    sidentifier_type = 54
    sidentifier_len = 4
    sidentifier_addr = socket.inet_aton(MY_IP_ADDR)
    leasetime = 51
    leasetime_len = 4
    leasetime_time = b'\x00\x00\x02\x58'
    subnetmask = 1
    subnetmask_len = 4
    subnetmask_addr = socket.inet_aton('255.255.255.0')
    router = 3
    router_len = 4
    router_addr = socket.inet_aton('10.0.0.1')
    dname = 15
    dname_len = 9
    dname_name = b'\x74\x65\x73\x74\x65\x2e\x63\x6f\x6d' # teste.com
    dns = 6
    dns_len = 4
    dns_addr = socket.inet_aton(MY_IP_ADDR)
    end = 0xff
    end_padding = bytes.fromhex(''.join(['00' for i in range(0, 15)]))

    bootp_header = struct.pack('!BBBB4sHH', op, htype, hlen, hops, xid, secs, flags)
    addrs = struct.pack('!4s4s4s4s6s10s192s', ciaddr, yiaddr, siaddr, giaddr, chaddr, chapadding, padding)
    options_mtype = struct.pack('!4sBBB',magic_cookie, mtype, mtype_len, mtype_option)
    options_sidentifier = struct.pack('!BB4s', sidentifier_type, sidentifier_len, sidentifier_addr)
    options_leasetime = struct.pack('!BB4s', leasetime, leasetime_len, leasetime_time)
    options_subnet = struct.pack('!BB4s', subnetmask, subnetmask_len, subnetmask_addr)
    options_router = struct.pack('!BB4s', router, router_len, router_addr)
    options_dns = struct.pack('!BB9sBB4sB15s', dname, dname_len, dname_name, dns, dns_len, dns_addr, end, end_padding)

    return bootp_header + addrs + options_mtype + options_sidentifier + options_leasetime + options_subnet + options_router + options_dns


def unpack_udp(packet):
    udph = struct.unpack('!HHHH', packet[20+ETH_LENGTH:28+ETH_LENGTH])
    udp_sport = udph[0]
    udp_dport = udph[1]
    udp_len = udph[2]

    return (udp_sport, udp_dport, udp_len)


def udp(packet, ip_saddr, ip_daddr, data, invert_ports=False):
    (udp_sport, udp_dport, udp_len) = unpack_udp(packet)

    if invert_ports:
        udp_sport, udp_dport = udp_dport, udp_sport

    udp_check = 0

    udp_header = struct.pack('!HHHH', udp_sport, udp_dport, udp_len, udp_check)

    udp_pseudo_header = struct.pack('!4s4sBBH', ip_saddr, ip_daddr, udp_check, socket.IPPROTO_UDP, udp_len)

    udp_check = checksum(udp_pseudo_header + udp_header + data)

    udp_header = struct.pack('!HHHH', udp_sport, udp_dport, udp_len, udp_check)

    return udp_header + data


try:
    (s0, eth0_mac_addr) = create_socket('eth0')
except OSError as msg:
    print('Error' + str(msg))
    sys.exit(1)

print('Sockets created!')

inputs = [s0]
outputs = []
message_queues = {}

while inputs:
    readable, writable, exceptional = select.select(inputs, outputs, inputs)
    for s in readable:
        (packet, addr) = s.recvfrom(65536)

        eth_header = packet[:ETH_LENGTH]

        eth = struct.unpack('!6s6sH', eth_header)
        protocol = eth[2]

        interface = 'eth0' if s is s0 else 'eth1'
        print('Received from ' + interface)
        print('MAC Dst: ' + bytes_to_mac(eth[0]))
        print('MAC Src: ' + bytes_to_mac(eth[1]))
        print('Type: ' + hex(protocol))
        print('{0}'.format(protocol))

        nexthdr = packet[ETH_LENGTH:]

        if protocol == 2048 and s is s0:
            dest_mac = eth[1]
            source_mac = eth0_mac_addr

            eth_hdr = struct.pack('!6s6sH', dest_mac, source_mac, protocol)

            (ip_header, ip_proto, ip_saddr, ip_daddr) = pack_ip_header(packet, None, None)

            if ip_proto == socket.IPPROTO_UDP:
                (udp_sport, udp_dport, udp_len) = unpack_udp(packet)
                
                if udp_sport == 68 and udp_dport == 67 and udp_len == 308:
                    (xid, chaddr, mtype_option) = unpack_bootp(packet)

                    if mtype_option == DHCP_DISCOVER:
                        ip = find_ip(dest_mac)
                        if ip is None:
                            ip = find_free_ip()
                            ip['mac'] = dest_mac
                            (ip_header, ip_proto, ip_saddr, ip_daddr) = pack_ip_header(packet, MY_IP_ADDR, ip['ip'])
                            data = pack_bootp(xid, ip_daddr, dest_mac)
                            s0.send(eth_hdr + ip_header + udp(packet, ip_saddr, ip_daddr, data, True))
                    elif mtype_option == DHCP_REQUEST:
                        ip = find_ip(dest_mac)
                        if ip is not None:
                            ip_daddr = ip['ip']
                            (ip_header, ip_proto, ip_saddr, ip_daddr) = pack_ip_header(packet, MY_IP_ADDR, ip['ip'])
                            data = pack_bootp(xid, ip_daddr, dest_mac, False)
                            s0.send(eth_hdr + ip_header + udp(packet, ip_saddr, ip_daddr, data, True))
                    elif mtype_option == DHCP_RELEASE:
                        release_ip(dest_mac)
