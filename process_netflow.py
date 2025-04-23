from parser import parse_netflow_data
from utils import *
import os
file_path = '/home/ren/flows_with_v5910'
f = open(file_path)
data = f.read()
flows = data.split('Flow Record:')
flow = []
count = 0
for i in flows:
    netflow_rec = parse_netflow_data(i)
    #flow.append(netflow_rec)
    if netflow_rec!= {}:
        print(i)
        print(netflow_rec)
        nv = find_netflow_version(netflow_rec['Flags'])
        print(nv)
        #print(type(file_path))
        #print(type(netflow_rec))
        #print(type(netflow_version_(netflow_rec['Flags'])))
        flow_raw = NetflowRawRecord(source=file_path,
                                    data=netflow_rec,
                                    netflow_version=nv,
                                    )
        flow_new = NetflowRecord(source=file_path,
                                 netflow_version=nv,
                                 src_addr=netflow_rec['src addr'],
                                 src_port=netflow_rec.get('src port',None),
                                 dst_addr=netflow_rec['dst addr'],
                                 dst_port=netflow_rec.get('dst port',None),
                                 first_datetime=epoch_datetime(int(netflow_rec['first'])),
                                 last_datetime=epoch_datetime(int(netflow_rec['last'])),
                                 collected_recv_datetime=epoch_datetime(int(netflow_rec['received at'])),
                                 flow_duration=int(netflow_rec['last'])-int(netflow_rec['first']),
                                 record_num=int(netflow_rec['RecordCount']),
                                 flow_size=int(netflow_rec['size']),
                                 in_byte=int(netflow_rec['in bytes']),
                                 in_packet=int(netflow_rec['in packets']),
                                 protocol=int(netflow_rec['proto']),
                                 tcp_flag=netflow_rec['tcp flags'],
                                 ip_version=get_ip_version(netflow_rec.get('IP version',None),netflow_rec['src addr']),
                                 rr_id=flow_raw.rr_id,
                                 attribution=False,
                                 attribution_date=None,
                                 src_known=False,
                                 src_malicious=False,
                                 src_malicious_source={},
                                 dst_known=False,
                                 dst_malicious=False,
                                 dst_malicious_source={},
                                )
        insert_netflow(flow_raw,flow_new)
        dst_user = UserNetflow(
                ip=netflow_rec['dst addr'],
                ip_version=get_ip_version(netflow_rec.get('IP version',None),netflow_rec['src addr']),
                src_connection_count=0,
                dst_connection_count=1)
        if insert_user(dst_user):
            update_user(dst_user)
        src_user = UserNetflow(
                ip=netflow_rec['src addr'],
                ip_version=get_ip_version(netflow_rec.get('IP version',None),netflow_rec['src addr']),
                src_connection_count=1,
                dst_connection_count=0)
        if insert_user(src_user):
            update_user(src_user)
        count+=1
        print(count)
f.close()
