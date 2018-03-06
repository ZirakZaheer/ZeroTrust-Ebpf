from bcc import libbcc, table
import ctypes as ct
class pinnedMap(table.HashTable):
        def __init__(self,map_path, keyType, valueType,maxEntries):
                map_fd = libbcc.lib.bpf_obj_get(ct.c_char_p(map_path))
                if map_fd < 0:
                        raise ValueError("failed to open map")
                self.map_fd = map_fd
                self.Key = keyType
                self.Leaf = valueType
                self.max_entries = maxEntries
