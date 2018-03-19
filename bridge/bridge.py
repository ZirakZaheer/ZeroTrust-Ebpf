from bcc import BPF,libbcc,table
from builtins import input
from ctypes import c_int
import ctypes as ct
from pyroute2 import IPRoute, IPDB
from simulation import Simulation
from netaddr import IPAddress
import os
from fcntl import ioctl
from pytap2 import *

ipr = IPRoute()
ipdb = IPDB(nl=ipr)

testNum = "2"
pathToPin = "/sys/fs/bpf/context"
num_hosts = 2
null = open("/dev/null", "w")
TASK_COMM_LEN = 16
class Data(ct.Structure):
        _fields_ = [("pid", ct.c_ulonglong),
		    ("inum", ct.c_ulonglong),
                    ("lport", ct.c_ulonglong),
                    ("comm", ct.c_char *  TASK_COMM_LEN)]

class PinnedMap(table.HashTable):
	def __init__(self,map_path, keyType, valueType,maxEntries):
		map_fd = libbcc.lib.bpf_obj_get(ct.c_char_p(map_path))
		if map_fd < 0:
			raise ValueError("failed to open map")
		self.map_fd = map_fd
		self.Key = keyType
		self.Leaf = valueType
		self.max_entries = maxEntries

def mapOperation(srcMap, dstMap):
	# find the right value and key
	print "map operation"
	srcValues = srcMap.values()
	print srcValues
	print dstMap.map_fd
	firstKey = 1
	firstValue = srcValues[0]
	dstMap.__setitem__(ct.c_int(firstKey), firstValue) 
	#print libbcc.lib.bpf_update_elem(dstMap.map_fd, ct.byref(ct.c_int(firstKey)), ct.byref(firstvalue), 0)
	print srcMap.map_fd
	print  dstMap.__getitem__(ct.c_int(firstKey))
#	for value in srcValues:
#		print value
#		if value.pid == "15323":
#			key = 1001 #bind between {nginx : 1001}
#			libbcc.lib.bpf_update_elem(dstMap.map_fd, ct.byref(key), ct.byref(value),0)

      

bridge_code = BPF(src_file="bridge.c")


# do not change these values: tap interface setup

TUNSETIFF = 0x400454ca
TUNSETOWNER = TUNSETIFF + 2
IFF_TUN = 0x0001
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
tapFD = 0
# this function returns fd to the newly created tap interface
def tapDev(tapname, mode):
    tap = os.open('/dev/net/tun', mode | os.O_NONBLOCK)
    ifr = struct.pack('16sH', tapname, IFF_TAP | IFF_NO_PI)
    ioctl(tap, TUNSETIFF, ifr)
    return tap


def skb_event_handler(cpu, data, size):
    class SkbEvent(ct.Structure):
        _fields_ =  [
                        ("magic", ct.c_uint32),
                        ("raw", ct.c_ubyte * (size - ct.sizeof(ct.c_uint32)))
                    ]
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents

        #parse those packets to see the size and mapping of the packets

        #executer actions
                #fetch context
                #context 
                #insert in local context table (in ebpf maps)

        #rebuild packet using scapy
                #require a raw socket and needs to know the interface to which to write packets

    icmp_type = int(skb_event.raw[54])
    # Only print for echo request
    print bytes(skb_event.raw)
    os.write(openedDev, skb_event.raw)



class BridgeSimulation(Simulation):
    def __init__(self, ipdb):
        super(BridgeSimulation, self).__init__(ipdb)

    def start(self):
        # Ingress = attached to tc ingress class on bridge
        # Egress = attached to tc engress class on namespace (outside) interface
        # Loading bpf functions/maps.
        #bridge_code = BPF(src_file="bridge.c")
        ingress_fn = bridge_code.load_func("handle_ingress", BPF.SCHED_CLS)
        egress_fn  = bridge_code.load_func("handle_egress", BPF.SCHED_CLS)
        mac2host   = bridge_code.get_table("mac2host")
        conf       = bridge_code.get_table("conf")
        policyMap = bridge_code.get_table("DEMO_MAP1") # {u32 , data_t}
        

	# Creating dummy interface behind which ebpf code will do bridging.
        ebpf_bridge = ipdb.create(ifname="ebpf_br", kind="dummy").up().commit()
        ipr.tc("add", "ingress", ebpf_bridge.index, "ffff:")
        ipr.tc("add-filter", "bpf", ebpf_bridge.index, ":1", fd=egress_fn.fd,
           name=egress_fn.name, parent="ffff:", action="drop", classid=1)
    

	# Creating tap interface behind which we run the ebpf code that forwards the packet to the ebpf bridge
	#	tafFd = tapDev("tap0", os.O_RDWR)
	tap0 = ipr.link_lookup(ifname="tap0")[0]

	ipr.tc("add", "ingress", tap0, "ffff:")
	ipr.tc("add-filter", "bpf", tap0, ":1", fd=ingress_fn.fd,
		name=ingress_fn.name, parent="ffff:", action="drop", classid=1)
	
        # Passing bridge index number to dataplane module
        conf[c_int(0)] = c_int(ebpf_bridge.index)
        # Setup namespace and their interfaces for demostration.
        host_info = []
	host_info.append(self._create_ns("vport_test2", ipaddr="174.17.0.5/16")) #vport_test5
        host_info.append(self._create_ns("vport_test3",ipaddr="174.17.0.3/16")) #vport_test4
        # For each namespace that want to connect to the ebpf bridge
        # We link it to the dummy interface behind which we run ebpf learning/forwarding code
        # logically: Attaching individual namespace interface into the ebpf bridge.
        # programmatically: running ebpf engress code on each interface
        temp_index=1
        for host in host_info:
	    print host[1].index
            ipr.tc("add", "ingress", host[1].index, "ffff:")
            ipr.tc("add-filter", "bpf", host[1].index, ":1", fd=ingress_fn.fd,
                   name=ingress_fn.name, parent="ffff:", action="drop", classid=1)
            # Passing namespace interface info to dataplane module.
            conf[c_int(temp_index)] = c_int(host[1].index)
            temp_index=temp_index+1

try:
    tapFD = tapDev("tap0", os.O_RDWR)
    print "testing"
    bridge_code["skb_events"].open_perf_buffer(skb_event_handler)
    contextMap = bridge_code.get_table("DEMO_MAP1")
    libbcc.lib.bpf_obj_pin(contextMap.map_fd, ct.c_char_p(pathToPin))
    policyMap = bridge_code.get_table("POLICY_MAP")
    libbcc.lib.bpf_obj_pin(policyMap.map_fd, ct.c_char_p("/sys/fs/bpf/policy"))
    ifinum = bridge_code.get_table("if_inum")
    libbcc.lib.bpf_obj_pin(ifinum.map_fd, ct.c_char_p("/sys/fs/bpf/ifinum"))
    text = raw_input("Maps setup done: Press a Key to continue")
    sim = BridgeSimulation(ipdb)
    sim.start()
#    os.close(tapFD)
    icmp_req = b'E\x00\x00(\x00\x00\x00\x00@\x01`\xc2\n\x00\x00\x04\x08\x08'\
    '\x08\x08\x08\x00\x0f\xaa\x00{\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00test'
#os.write(ftun, icmp_req)

    os.write(tapFD, icmp_req)
    os.close(tapFD)
    while True:
        bridge_code.perf_buffer_poll()
    input("Press enter to quit:")
except Exception,e:
    print str(e)
    if "sim" in locals():
        for p in sim.processes: p.kill(); p.wait(); p.release()
finally:
    if "ebpf_br" in ipdb.interfaces: ipdb.interfaces["ebpf_br"].remove().commit()
    if "tap0" in ipdb.interfaces: ipdb.interfaces["tap0"].remove().commit()
    if "sim" in locals(): sim.release()
    ipdb.release()
    os.close(tapFD)
    null.close()


