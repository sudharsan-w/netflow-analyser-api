def parse_netflow_data(flow_data):
    netflow_dict = {}
    lines = flow_data.splitlines()
    print(len(lines))
    for line in lines:
        # Ignore empty lines
        if not line.strip():
            continue
        parts = line.split('=')
        if len(parts) != 2:
            continue  # Skip any malformed lines
        key = parts[0].strip()
        value = parts[1].strip()
        if key in ['first','last','received at','proto','tcp flags']:
            value = value.split(' ')[0]
        netflow_dict[key] = value
    return netflow_dict

