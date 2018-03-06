from bcc import BPF,table, libbcc
from pyroute2 import IPDB
import ctypes as ct
ipdb = IPDB()
from libnl.linux_private.rtnetlink import RTA_DATA, RTA_NEXT, RTA_OK, RTM_GETLINK, ifinfomsg, rtgenmsg
from libnl.msg import nlmsg_data, nlmsg_hdr
from subprocess import check_output
import pprint
import json
pp = pprint.PrettyPrinter(indent=3)
from enum import Enum
import PinnedMap
class NetlinkEvents(Enum):
    # A new neighbor has appeared
    RTM_NEWNEIGH = 'RTM_NEWNEIGH'
    # We're no longer watching a certain neighbor
    RTM_DELNEIGH = 'RTM_DELNEIGH'
    # A new network interface has been created
    RTM_NEWLINK = 'RTM_NEWLINK'
    # A network interface has been deleted
    RTM_DELLINK = 'RTM_DELLINK'
    # An IP address has been added to a network interface
    RTM_NEWADDR = 'RTM_NEWADDR'
    # An IP address has been deleted off of a network interface
    RTM_DELADDR = 'RTM_DELADDR'
    # A route has been added to the routing table
    RTM_NEWROUTE = 'RTM_NEWROUTE'
    # A route has been removed from the routing table
    RTM_DELROUTE = 'RTM_DELROUTE'



ifInum = PinnedMap.pinnedMap("/sys/fs/bpf/ifinum",ct.c_uint32, ct.c_uint64, 1024)


#def new_address_callback(ipdb, netlink_message, action):
 #   if action == 'RTM_NEWADDR':
  #      pp.pprint(netlink_message)

def new_dev_callback(ipdb, netlink_message, action):
    if action == 'RTM_NEWLINK':
        #pp.pprint(netlink_message)
	nldict = dict(netlink_message)
	print "handling call back"
	ifindex = nldict['index']
	ifnametup = nldict['attrs'][0]
	ifname = ifnametup[1]
	nsPath = check_output(["sudo","docker", "inspect", "--format"," '{{.NetworkSettings.SandboxKey}}'",ifname[:-1]])
	nsPath = nsPath.rstrip('\r\n')[1:]
	nsPath = json.dumps(str(nsPath)).replace("'","")
	nsPath = nsPath.replace('"', "")
	out = check_output(["sudo", "ls", "-Li", nsPath])
	inum = out.split(" ")[0]
	print inum
	ifInum[ct.c_uint(ifindex)] = ct.c_uint64(int(inum))
	print ifInum[ct.c_uint(ifindex)]
#addr_callback = ipdb.register_callback(new_address_callback)
dev_callback = ipdb.register_callback(new_dev_callback)
input()
#ipdb.unregister_callback(addr_callback)
ipdb.unregister_callback(dev_callback)
