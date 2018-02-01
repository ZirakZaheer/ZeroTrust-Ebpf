from bcc import libbcc, table
import ctypes as ct
import sys

TASK_COMM_LEN = 16
class Data(ct.Structure):
        _fields_ = [("pid", ct.c_ulonglong),
                    ("ts", ct.c_ulonglong),
                    ("comm", ct.c_char *  TASK_COMM_LEN)]

class AccessPinnedArray(table.HashTable):
	def __init__(self, map_path, keytype, leaftype, max_entries):
		map_fd = libbcc.lib.bpf_obj_get(ct.c_char_p(map_path))
		if map_fd < 0:
			raise ValueError("Failed to open eBPF map")
		self.map_fd = map_fd
		self.Key = keytype
		self.Leaf = leaftype
		self.max_entries = max_entries

def readCounter(map_path, index):
	counter = AccessPinnedArray(map_path, ct.c_uint32, Data, 1024);
	
	values = counter.values()
	print("reading Values")
	print(len(values))
	data = values[1]
	print ("anything")
	print(data.pid)
	
	#event = ct.cast(data, Data).contents	
	event = data
	print("testing value and types")	
	#print(data.value)
	#print event
	print("%-16s %-6d %s" % (event.comm, event.pid,
        "Hello, perf_output!"))
	print(event.comm)


if __name__ == '__main__':
	path = sys.argv[1]
	index = sys.argv[2]	
	readCounter(path, index) 
