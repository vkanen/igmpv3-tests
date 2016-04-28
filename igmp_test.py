#!/usr/bin/env python
#
# send IGMPv2/IGMPv3 join/leave report msgs to 224.0.0.22 (IGMPv3) or
# MC group destination address (IGMPv2)
#
# host routing must be set up before hand to send the packets
# out from correct interface. For example, in Linux it could be
# something like: "route add -net 224.0.0.0/4 dev <ifname>".

from socket import *
from igmp_packets import *
import argparse
import time
import datetime
import os

############ start of editable variables ############
VERSION = 1.0                                       #
MAX_NUM_OF_GROUPS = 16000                           # 
ETHERNET_HEADER_SIZE = 14                           # assuming no tagging
############ end of editable variables ##############

# exitcodes
IGMP_OK = 0
IGMP_TEST_INSUFFICIENT_PRIVILEDGES = 126 
IGMP_TEST_INVALID_ARG = 128
IGMP_TEST_KILL = 137
IGMP_TEST_ERROR = 1

# multicast addresses
ALL_MC_ROUTERS_IN_LAN = '224.0.0.2'
ALL_IGMPV3_ROUTERS_IN_LAN = '224.0.0.22'

slock = threading.Semaphore() # socket is global. For now, only one task per socket though...

parser = argparse.ArgumentParser(description="Send IGMP report message(s) to simulate client's 'join'- or 'leave' actions to/from a multicast\n group. Default join type (for IGMPv3) is 'for all sources': (*,G)", 
                                 epilog='Example of use: igmp_test.py -n 100 -s 192.168.1.2 -t join')
parser.add_argument('-n', '--number', help='number of different mcgs to join. The script will choose these automatically', 
                    type=int, default=1)
parser.add_argument('-d', '--delta', help='delay in microseconds between sent packets', type=int, default=100)
parser.add_argument('-m', '--mcgroup', help='first address in the IPv4 mcg range', type=str, default='225.0.0.1')
parser.add_argument('-D', '--dump', help='print hex dump of sent packets', action='store_true')
parser.add_argument('-l', '--list_of_srcs', help='source address list for filter-mode: addresses to be included or excluded', type=str, nargs='+', default=[])
parser.add_argument('-f', '--filter_mode', help='mode type for source address list', type=str, choices=['include','exclude'],default='exclude')
parser.add_argument('-i', '--igmp_version', help='IGMP version: v2 or v3', type=str, choices=['v2','v3'], default='v3')
required = parser.add_argument_group('required named arguments')
required.add_argument('-s', '--source', help='src address of sent packets', type=str, required=True)
required.add_argument('-t', '--type', help="IGMP report message type", type=str, choices=['join','leave'], required=True)

args = parser.parse_args()
if not(args.number in range(1, MAX_NUM_OF_GROUPS)):
    print 'Error: invalid number of multicast groups. Max number is ' + str(MAX_NUM_OF_GROUPS)
    sys.exit(IGMP_TEST_INVALID_ARG)

if args.source != '':
    try:        
        inet_aton(args.source)
    except error:
        print 'Error: invalid source IP address: ' + args.source
        sys.exit(IGMP_TEST_INVALID_ARG)

if not is_ipv4_mc(args.mcgroup):
    print 'Error: invalid IPv4 multicast address '
    sys.exit(IGMP_TEST_INVALID_ARG)

def is_ipv4_unicast(a):
    # todo:
    return True

def parse_args(args):
    if args.filter_mode == 'include' and args.type == 'join' and args.list_of_srcs == []:
        print "Error: trying to include empty multicast src-list in a join message."
        sys.exit(IGMP_TEST_INVALID_ARG)
    if args.igmp_version == 'v2' and args.list_of_srcs != []:
        print "Error: trying to use multicast source list while IGMPv2 is selected: unsupported action"
        sys.exit(IGMP_TEST_INVALID_ARG)
    for s in args.list_of_srcs:
        if not is_ipv4_mc(s):
            print "Error: invalid source address in the src address list"
            sys.exit(IGMP_TEST_INVALID_ARG)
    #todo: check argument validity. E.g. no source-address-lists in "leave" msg etc

def signal_handler(signal, frame):
    global stop
    print 'Test interrupted by Ctrl+C!'
    stop = True

class igmp_t(threading.Thread):
    def run(self):    
        src_list = args.list_of_srcs
        global stop
        inc = 0
        sent_bytes = 0
        a0 = args.mcgroup.split('.')[0]
        a1 = args.mcgroup.split('.')[1]
        a2 = args.mcgroup.split('.')[2]
        a3 = args.mcgroup.split('.')[3]
        start_time = datetime.datetime.now()
        print 'test start time: ' + str(start_time)
        for i,j, k in product(range(int(a1),255),range(int(a2),255),range(int(a3),255)):
            if not stop:
                if inc < args.number:
                    group = a0 + '.{0}.{1}.{2}'.format(i,j,k) 
                else:
                    stop = True
                    break
                inc = inc + 1
                info_s = '{0:6} {1:27}'.format(str(inc) + '.', str((datetime.datetime.now())))
                info_s += '{0:41}'.format('Sending IGMP' + args.igmp_version + ' report (' + args.type + ') for group: ')
                info_s += '{0:15}'.format(group)
                print info_s
                igmp_r = mk_igmp_report(args.igmp_version, args.source, args.type, group, src_list, args.filter_mode)
                sent_bytes += len(igmp_r) + ETHERNET_HEADER_SIZE

                if args.dump == True:
                    dump_packet(igmp_r)                
                if args.igmp_version == '2':
                    dst = ALL_MC_ROUTERS_IN_LAN
                else:
                    dst = ALL_IGMPV3_ROUTERS_IN_LAN
                    
                slock.acquire()                
                s.sendto(igmp_r, (dst, 0))
                slock.release()
                sleep(float(args.delta)/float(1000000))
            else:
                break
        # print some test stats
        stop_time = datetime.datetime.now()
        test_delta = stop_time - start_time
        print '\ntest duration was ' + str(test_delta)
        avg_rate = (sent_bytes * 8) / float(test_delta.microseconds + test_delta.seconds * 1000000)
        pkts_per_second = inc / float(test_delta.microseconds/float(1000000) + test_delta.seconds)
        info_s = str(sent_bytes) + ' bytes sent at rate ' 
        info_s += format('%.3f' % avg_rate) + ' Mbps (avg ' + format('%.0f' % pkts_per_second) + ' packets/s)'
        print info_s

parse_args(args)
if os.geteuid() != 0: # accessing system sockets require root priviledges
    print('Indufficient priviledges to run the script: you need to be a root to execute this. Hint: try sudo ./igmp_test.py')
    sys.exit(IGMP_TEST_INSUFFICIENT_PRIVILEDGES)

s = socket( AF_INET, SOCK_RAW, IPPROTO_RAW )
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
s.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, 2)
stop = False

print 'Press Ctrl+C to quit'
join_thread = igmp_t()
join_thread.start()
signal.signal(signal.SIGINT, signal_handler)

while(not stop):
    sleep(0.1)

join_thread.join()
s.close()
