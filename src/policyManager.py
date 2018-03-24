from bcc import libbcc, table
import ctypes as ct
import sys




TASK_COMM_LEN = 16
class Policy(ct.Structure):
        _fields_ = [
                    ("srcContext",ct.c_char * TASK_COMM_LEN),
                    ("dstContext",ct.c_char * TASK_COMM_LEN),
		    ("action", ct.c_uint32)
	           ]

class AccessPinnedArray(table.HashTable):
        def __init__(self, map_path, keytype, leaftype, max_entries):
                map_fd = libbcc.lib.bpf_obj_get(ct.c_char_p(map_path))
                if map_fd < 0:
                        raise ValueError("Failed to open eBPF map")
                self.map_fd = map_fd
                self.Key = keytype
                self.Leaf = leaftype
                self.max_entries = max_entries

policyMap = AccessPinnedArray("/sys/fs/bpf/policy",ct.c_long, Policy, 1024)

if __name__ == '__main__':
	command = raw_input("command:   ")
	if command == 'add':
		src = raw_input("src context:   ")
		dst = raw_input("recv context:  ")
		action = raw_input("action:  ")
		newPolicy = Policy()
		newPolicy.srcContext = src
		newPolicy.dstContext = dst
		newPolicy.action = int(action)
		policyKey = sum([(ord(i)) for i in src]) + sum([ord(i) for i in dst])
		print policyKey
		policyMap[ct.c_long(policyKey)] = newPolicy

		print "policy added with key ", policyKey
