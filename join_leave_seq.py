#!/usr/bin/env python
#
# send IGMPv3 join/leave msgs to "all IGMPv3 capable routers" (224.0.0.22)
# host routing must be set up before hand to send the packets
# out from correct interface. For example, in Linux it could be
# something like: "route add 224.0.0.0/8 dev <ifname>".
#
# Raw sockets are used here so we can by-pass Kernel's stack and interface
# settings.

from string import *
from igmp_packets import *
import argparse


############ start of editable variables ############
MAX_NUM_OF_JOIN_LEAVE = 100000
############ end of editable variables ##############

parser = argparse.ArgumentParser(description='Send IGMPv3 join-leave msg sequences to 224.0.0.22 (all IGMPv3 routers)', 
                                 epilog='Example of use: join_leave_seq.py -n 100')
parser.add_argument('-n', '--number', help='number of different mcgs to join. The script will choose these automatically', 
                    type=int, default=1)
parser.add_argument('-d', '--delta', help='delay in milliseconds between sent packets', type=int, default=100)
parser.add_argument('-m', '--mcgroup', help='first address in the IPv4 MC range', type=str, default='225.0.0.1')
parser.add_argument('-D', '--dump', help='print hex dump of sent packets', action='store_true')
parser.add_argument('-i', '--igmp_version', help='IGMP version: v2 or v3', type=str, choices=['v2','v3'], default='v3')
required = parser.add_argument_group('required named arguments')
required.add_argument('-s', '--source', help='IGMP message source', type=str, required=True)
args = parser.parse_args()

if not(args.number in range(1, MAX_NUM_OF_JOIN_LEAVE)):
    print 'Error: invalid number of multicast groups. Max number is ' + str(MAX_NUM_OF_GROUPS)
    sys.exit(1)

dst = '224.0.0.22' # "to all IGMPv3 capable routers"
slock = threading.Semaphore() # socket is global. For now, only one task per socket though...

def signal_handler(signal, frame):
    global stop
    print 'Test interrupted by Ctrl+C!'
    stop = True

class igmp_t(threading.Thread):
    def run(self):
        global stop
        inc = 0
        a1 = args.mcgroup.split('.')[1]
        a2 = args.mcgroup.split('.')[2]
        a3 = args.mcgroup.split('.')[3]
        for i,j, k in product(range(int(a1),255),range(int(a2),255),range(int(a3),255)):
            if not stop:
                if inc < args.number:
                    group = '225.{0}.{1}.{2}'.format(i,j,k) 
                else:
                    stop = True
                    break
                for send_loop in (0,1):
                    if send_loop == 0:
                        report_type = 'join'
                    else:
                        report_type = 'leave'
                    info_s = '{0:4} {1:41}'.format(str(inc) + ':', 'Sending IGMP' + args.igmp_version + ' report (' + report_type + ') for group: ')
                    info_s += '{0:15}'.format(group)
                    #print str(inc) + 'Sending IGMP' + args.igmp_version + ' report (' + report_type + ') for group: ' + group
                    print info_s
                    igmp_r = mk_igmp_report(args.igmp_version, args.source, report_type, group, [])
                    if (args.dump == True):
                        dump_packet(igmp_r)
                    slock.acquire()
                    s.sendto(igmp_r, (dst, 0))
                    slock.release()                
                    sleep(float(args.delta)/float(1000))
                inc = inc + 1
            else:
                break

s = socket( AF_INET, SOCK_RAW, IPPROTO_RAW )
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
s.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, 2)
stop = False

print 'Press Ctrl+C to quit'
test_tread = igmp_t()
test_tread.start()
signal.signal(signal.SIGINT, signal_handler)

# main thread could do something useful too...
while(not stop):
    sleep(1)

test_tread.join()
s.close()
