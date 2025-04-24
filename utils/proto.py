L4_PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}
L4_REVERSE = {
    v: k for k, v in L4_PROTOCOL_MAP.items()
}
def l4_proto(proto_num):
    return L4_PROTOCOL_MAP.get(proto_num, None)

def l4_proto_reverse(proto: str):
    if proto in L4_REVERSE:
        return L4_REVERSE[proto]
    if str(proto).isdigit():
        return int(proto)
    return None