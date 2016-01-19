#!/usr/bin/python

# send IGMPv3 join msgs to "all IGMPv3 capable routers" (224.0.0.22)
# host routing must be set up before hand to send the packets
# out from correct interface. For example, in Linux it could be
# something like: "route add 224.0.0.0/8 dev <ifname>".

from igmp_packets import *
import argparse

############ start of editable variables ############
MAX_NUM_OF_GROUPS = 16000
############ end of editable variables ##############

dst = '224.0.0.22' # "to all IGMPv3 capable routers"
slock = threading.Semaphore() # socket is global. For now, only one task per socket though...

parser = argparse.ArgumentParser(description='Send IGMPv3 join packets to 224.0.0.22 (all IGMPv3 routers)', 
                                 epilog='Example of use: join_test.py -n 100')
parser.add_argument('-n', '--number', help='number of different mcgs to join. The script will choose these automatically', 
                    type=int, default=10)
parser.add_argument('-d', '--delta', help='delay in milliseconds between sent packets', type=int, default=100)
parser.add_argument('-m', '--mcgroup', help='first address in the IPv4 MC range', type=str, default='225.0.0.1')
parser.add_argument('-D', '--dump', help='print hex dump of sent packets', action='store_true')
required = parser.add_argument_group('required named arguments')
required.add_argument('-s', '--source', help='IGMP message source', type=str, required=True)
args = parser.parse_args()

if not(args.number in range(1, MAX_NUM_OF_GROUPS)):
    print 'Error: invalid number of multicast groups. Max number is ' + str(MAX_NUM_OF_GROUPS)
    sys.exit(1)

if args.source != '':
    try:        
        inet_aton(args.source)   
    except error:
        print 'Error: invalid source IP address: ' + args.source
        sys.exit(2)

if not is_ipv4_mc(args.mcgroup):
    print 'Error: invalid IPv4 multicast address '
    sys.exit(1)

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
            if (not stop):
                if inc < args.number:
                    group = '225.{0}.{1}.{2}'.format(i,j,k) 
                else:
                    stop = True
                    break
                inc = inc + 1
                print str(inc) + ': Sending IGMP report for group: ' + group
                igmp_r = mk_igmp_join(args.source, group)
                if (args.dump == True):
                    dump_packet(igmp_r)
                slock.acquire()
                s.sendto(igmp_r, (dst, 0))
                slock.release()
                sleep(float(args.delta)/float(1000))
            else:
                break

s = socket( AF_INET, SOCK_RAW, IPPROTO_RAW )
s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
s.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, 2)
stop = False

print 'Press Ctrl+C to quit'
join_thread = igmp_t()
join_thread.start()
signal.signal(signal.SIGINT, signal_handler)

# main thread could do something useful too...
while(not stop):
    sleep(1)

join_thread.join()
s.close()
