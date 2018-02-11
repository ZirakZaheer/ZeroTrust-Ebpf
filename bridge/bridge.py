from bcc import BPF,libbcc,table
from builtins import input
from ctypes import c_int
import ctypes as ct
from pyroute2 import IPRoute, IPDB
from simulation import Simulation
from netaddr import IPAddress
ipr = IPRoute()
ipdb = IPDB(nl=ipr)

num_hosts = 2
null = open("/dev/null", "w")
TASK_COMM_LEN = 16
class Data(ct.Structure):
        _fields_ = [("pid", ct.c_ulonglong),
                    ("ts", ct.c_ulonglong),
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
	srcValues = srcMap.values()
	for value in srcValues:
		if value.comm == "nginx":
			key = 1001 #bind between {nginx : 1001}
			libbcc.lib.bpf_update_elem(dstMap.map_fd, ct.byref(key), ct.byref(value),
                                  0)

      



class BridgeSimulation(Simulation):
    def __init__(self, ipdb):
        super(BridgeSimulation, self).__init__(ipdb)

    def start(self):
        # Ingress = attached to tc ingress class on bridge
        # Egress = attached to tc engress class on namespace (outside) interface
        # Loading bpf functions/maps.
        bridge_code = BPF(src_file="bridge.c")
        ingress_fn = bridge_code.load_func("handle_ingress", BPF.SCHED_CLS)
        egress_fn  = bridge_code.load_func("handle_egress", BPF.SCHED_CLS)
        mac2host   = bridge_code.get_table("mac2host")
        conf       = bridge_code.get_table("conf")
        policyMap = bridge_code.get_table("DEMO_MAP1") # {u32 , data_t}
#	if ret != 0:
#           raise Exception("Failed to pin map")
        # Creating dummy interface behind which ebpf code will do bridging.
        ebpf_bridge = ipdb.create(ifname="ebpf_br", kind="dummy").up().commit()
        ipr.tc("add", "ingress", ebpf_bridge.index, "ffff:")
        ipr.tc("add-filter", "bpf", ebpf_bridge.index, ":1", fd=egress_fn.fd,
           name=egress_fn.name, parent="ffff:", action="drop", classid=1)
    
# fetch the map created in bridge.c (Policy MAP) and the map created in bpf trace function (DEMO_MAP)
# retrieve the context from one and pass it to the other
	#srcMap = PinnedMap("/sys/fs/bpf/test", ct.c_uint32, Data, 1024)
	#mapOperation(srcMap, policyMap)		
        #pinmap 
        libbcc.lib.bpf_obj_pin(policyMap.map_fd, ct.c_char_p("/sys/fs/bpf/test1"))


        # Passing bridge index number to dataplane module
        conf[c_int(0)] = c_int(ebpf_bridge.index)
#	print ipdb
#	print ipdb.interfaces
        # Setup namespace and their interfaces for demostration.
        host_info = []
	host_info.append(self._create_ns("vport_test2", ipaddr="174.17.0.5/16")) #vport_test5
        host_info.append(self._create_ns("vport_test3",ipaddr="174.17.0.3/16")) #vport_test4
#	print host_info
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
    sim = BridgeSimulation(ipdb)
    sim.start()
    input("Press enter to quit:")
except Exception,e:
    print str(e)
    if "sim" in locals():
        for p in sim.processes: p.kill(); p.wait(); p.release()
finally:
    if "ebpf_br" in ipdb.interfaces: ipdb.interfaces["ebpf_br"].remove().commit()
    if "sim" in locals(): sim.release()
    ipdb.release()
    null.close()


