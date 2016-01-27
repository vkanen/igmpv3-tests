# IGMPv3 packet contstruction functions

from socket import *
from struct import *
from itertools import *
from time import *
import sys
import IN
import threading
import signal

IGMPV2_REPORT = 0x16
IGMPV3_REPORT = 0x22
IGMP_LEAVE = 0x17
IGMP_EXCLUDE = 0x04
IGMP_INCLUDE = 0x03
IGMPV3_ALL_ROUTERS = '224.0.0.22'

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

def mk_igmp_msg(msg_type, group, record_type, src_list):
    if msg_type == IGMPV2_REPORT or msg_type == IGMP_LEAVE:
        pkt = pack('!BBH4s', msg_type, 0, 0, inet_aton(group))
    elif msg_type == IGMPV3_REPORT:
        pkt = pack('!BBHHHBBH', msg_type, 0x00, 0x0000, 0x0000, 0x0001, record_type,
                   0x00, len(src_list))
        pkt += pack('!4s', inet_aton(group))
        for a in src_list:
            pkt += pack('!4s', inet_aton(a))
    else:
        print 'unsupported report type: ' + str(msg_type)
        sys.exit(1)
    return pkt

def mk_igmpv3_join_msg(src, group, src_list):
    if src_list == []:
        rec_type = IGMP_EXCLUDE # exclude src list data sources
    else:
        rec_type = IGMP_INCLUDE # include empty list => "all sources"
    pkt = mk_igmp_msg(IGMPV3_REPORT, group, rec_type, src_list) 
    return pkt

def mk_igmpv3_leave_msg(src, group, src_list):
    return mk_igmp_msg(IGMPV3_REPORT, group, IGMP_INCLUDE, [])

def mk_igmpv2_join_msg(src, group, src_list):
    return mk_igmp_msg(IGMPV2_REPORT, group, 0, [])

def mk_igmpv2_leave_msg(src, group, src_list):
    return mk_igmp_msg(IGMP_LEAVE, group, 0, [])

##########################################################################################################
#igmp_version: 'v2', 'v3'
#src IP src address of the MC subscriber
#report type: 'join', 'leave'
#group: IPv4 MC group
#src_list: list of MC sources if source specific MC is used (leave empty, [], for (*,G) entries) or for v2
##########################################################################################################
def mk_igmp_report(igmp_version, src, report_type, group, src_list):
    if igmp_version == 'v3':
        dst = IGMPV3_ALL_ROUTERS
        if report_type == 'join':
            mk_igmp = mk_igmpv3_join_msg
        elif report_type == 'leave':
            mk_igmp = mk_igmpv3_leave_msg
            src_list = []            
        else:
            print "unsupported IGMP report type " + report_type + ". Supported values: 'join' and 'lave'" 
            sys.exit(1)
    elif igmp_version == 'v2':
        dst = group
        if report_type == 'join':
            mk_igmp = mk_igmpv2_join_msg
            src_list = []
        elif report_type == 'leave':
            mk_igmp = mk_igmpv2_leave_msg
            src_list = []
        else:
            print "unsupported IGMP report type " + report_type + ". Supported values: 'join' and 'lave'" 
            sys.exit(1)
    else:
        print "unsupported IGMP version " + igmp_version + ". Supported versions are 'v2' & 'v3'"
        sys.exit(1)

    igmp = mk_igmp(src, group, src_list)
    igmp = update_igmp_checksum(igmp)
    ip_hdr = mk_ip_hdr(src,dst)
    p = ip_hdr + igmp
    p = update_ip_checksum(p)
    return p
