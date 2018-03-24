#ebpf_bridge



leaving note: Mar 24
--- getting errors while using return value from policy check funtion, not sure why and whether i can use return values like this one  work around could be to write the value to a map and get it from there:i

This code implements bridge in ebpf.
Due to limitation of loops in ebpf code by varifier, Broadcast is limited to 15 hosts.
