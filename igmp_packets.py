#!/usr/bin/python

from socket import *
from struct import *
from itertools import *
from time import *
import sys
import IN
import threading
import signal

IGMP_EXCLUDE = 0x04
dst = '224.0.0.22'

#todo
def is_ipv4_mc(mcg):
    return True

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)

def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff

def update_igmp_checksum(pkt):
    cs = checksum(pkt)
    #print 'igmp checksum: ' + str(hex(cs))
    m = []
    for x in pkt:        
        m.append(ord(x))
    higher = (cs >> 8) & 0xff
    lower = cs & 0xff
    m[2] = lower
    m[3] = higher
    m = pack("%dB" % len(m), *m)
    return m

def update_ip_checksum(pkt):
    cs = checksum(pkt)
    #print 'ip hdr checksum: ' + str(hex(cs))
    m = []
    for x in pkt:        
        m.append(ord(x))
    higher = (cs >> 8) & 0xff
    lower = cs & 0xff
    m[10] = lower
    m[11] = higher
    m = pack("%dB" % len(m), *m)
    return m

def mk_ip_hdr(s, d):
    ip_ihl_len = 0x46 #8 bits
    ip_dscp = 0xc0 #8 bits
    ip_hdr_total_len = 0x0028 #16 bits
    ip_id = 0x0000 #16 bits
    ip_flags = 0x4000 #16 bits
    ip_ttl = 1 #8 bits
    ip_protocol = 0x02 #8 bits
    ip_cs = 0x0000 #16 bits (should filled by kernel but seems not???)
    #ip_src #32 bits
    #ip_dst #32 bits
    ip_options = 0x94040000 #32 bits
    #total len 24 bytes
    ip_header = pack('!BBHHHBBH4s4sI', ip_ihl_len, ip_dscp, ip_hdr_total_len,
                     ip_id, ip_flags, ip_ttl, ip_protocol, ip_cs, inet_aton(s),
                     inet_aton(d), ip_options)
    return ip_header
                     
def dump_packet(data):
    i = 0
    for x in data:
        if i == 4:
            print ''
            i = 0
        i += 1
        sys.stdout.write(' %0.2x' % ord(x))
    print ''

def mk_igmp_msg(group, src_list):
    num_of_sources = len(src_list)
    igmp_type = 0x22 #8 bits, igmp v3
    igmp_max_resp = 0x00 #8 bits, igmp v3
    igmp_checksum = 0x0000 #16 bits
    #igmp_group = 0x00000000 #32 bits
    igmp_s_qrv = 0x0000 #16 bits
    igmp_num_of_records = 0x0001 #16 bits
    igmp_record_type = IGMP_EXCLUDE #8bits (report)
    igmp_aux_data_len = 0x00 #8bits
    igmp_num_src = num_of_sources #16 bits
    igmp_src_list = [] #list of 32 bits addresses
    igmp_group = 0x00000000 #32 bits

    igmpv3_report = pack('!BBHHHBBH', igmp_type, igmp_max_resp, igmp_checksum,
                         igmp_s_qrv, igmp_num_of_records, igmp_record_type,
                         igmp_aux_data_len, igmp_num_src)
    for a in src_list:
        igmpv3_report += pack('!4s', inet_aton(a))
    igmpv3_report += pack('!4s', inet_aton(group))
    return igmpv3_report

def mk_igmp_join(src, group):
    ip_hdr = mk_ip_hdr(src,dst)    
    igmp = mk_igmp_msg(group, [])
    igmp = update_igmp_checksum(igmp)
    p = ip_hdr + igmp
    p = update_ip_checksum(p)
    return p
    
