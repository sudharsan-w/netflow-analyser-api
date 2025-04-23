from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional
from pymongo import MongoClient,UpdateOne
from datetime import datetime,timezone,timedelta
import uuid
import re
import ipaddress
MONGO_URI = 'mongodb://localhost:27017/'
class NetflowRecord(BaseModel):
    source: str #probably file name
    date_added: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: int = Field(default=1)
    netflow_version: int
    src_addr: str
    dst_addr: str
    src_port: Optional[str] = None
    dst_port: Optional[str] = None
    first_datetime: datetime
    last_datetime: datetime
    flow_duration: int
    collected_recv_datetime: datetime
    record_num: int
    flow_size: int
    in_byte: int
    in_packet: int
    protocol: int
    tcp_flag: str
    ip_version: str
    rr_id: str
    attribution: bool
    attribution_date: Optional[datetime] = None
    src_known: Optional[bool] = None #exclusions applied and then we only process false
    src_malicious: Optional[bool] = None #mapped after the malicious nature of the dest port 
    src_malicious_source: Optional[dict] = None
    dst_known: Optional[bool] = None #exclusions applied and then we only process false
    dst_malicious: Optional[bool] = None #mapped after the malicious nature of the dest port 
    dst_malicious_source: Optional[dict] = None

class NetflowRawRecord(BaseModel):
    source: str
    data: dict
    netflow_version: int
    rr_id: str = Field(default_factory=lambda: str(uuid.uuid4()))

class UserNetflow(BaseModel):
    usr_id: str = Field(default_factory=lambda : str(uuid.uuid4()))
    date_added: datetime = Field(default_factory = lambda: datetime.now(timezone.utc))
    date_updated: Optional[datetime] = None
    src_connection_count: int
    dst_connection_count: int
    malicous_ccount: Optional[int] = None #malicious connection counts based on dst or src
    ip: str
    ip_version: str
    asn: Optional[str] = None
    geo_location: Optional[dict] = None
    malicous_crefs: Optional[list] = None #flow refs
    schema_version: int = Field(default=1)
def insert_user(user: UserNetflow):
    client = MongoClient(MONGO_URI)
    db = client['Netflows']
    col = db['usr_netflow'] 
    user_dict = user.dict()
    jj = col.find_one({'ip':user_dict['ip']})
    already = True
    if not jj:
        col.insert_one(user_dict)
        already=False
    client.close()
    return already
def update_user(user: UserNetflow):
    client= MongoClient(MONGO_URI)
    db = client['Netflows']
    col = db['usr_netflow']
    jj = col.find_one({'ip':user.ip})
    src_count = jj['src_connection_count']+user.src_connection_count
    dst_count = jj['dst_connection_count']+user.dst_connection_count
    mal_cref = jj['malicous_crefs']
    malicous_ccount = None
    if jj['malicous_ccount']:
        malicous_ccount = jj['malicous_ccount']+user.malicous_ccount
    if mal_cref is not None and user.malicous_crefs is not None:
        mal_cref.extend(user.malicous_crefs)
    col.update_one({'ip':user.ip},{'$set':{'src_connection_count':src_count,
                                      'dst_connection_count': dst_count,
                                      'malicous_ccount':malicous_ccount,
                                      'asn':user.asn,
                                      'geo_location':user.geo_location,
                                      'malicous_crefs':mal_cref,
                                      'date_updated':datetime.now(timezone.utc)}})
    client.close()

def epoch_datetime(epoch):
    return datetime.fromtimestamp(epoch/1000, timezone.utc)

def find_netflow_version(text):
    m = re.search(r'NETFLOW\s+v(\d+)', text, re.IGNORECASE)
    if m:
        version = m.group(1)
        return int(version)  
    else:
        return None
def insert_netflow(flow_raw: NetflowRawRecord,flow_parsed: NetflowRecord):
    client = MongoClient(MONGO_URI)
    db = client['Netflows']
    raw_col = db['raw_netflow']
    par_col = db['parse_netflow']
    raw_dict = flow_raw.dict() 
    flow_par = flow_parsed.dict()
    par_filter = {'record_num':flow_par['record_num'],'src_addr':flow_par['src_addr'],'src_port':flow_par['src_port'],'dst_addr':flow_par['dst_addr'],'dst_port':flow_par['dst_port']}
    raw_filter = {'data':raw_dict['data']}
    jj = par_col.find_one(par_filter)
    jp = raw_col.find_one(raw_filter)
    if jj == None and jp == None:
        raw_col.insert_one(raw_dict)
        par_col.insert_one(flow_par)
    client.close()

def get_ip_version(ip_version,src_addr):
    if ip_version:
        return ip_version
    else:
        ip_obj = ipaddress.ip_address(src_addr)
        return '4' if ip_obj.version == 4 else '6'
def update_many_flows(ip,exclusion_status,mal_status,mal_src):
    client = MongoClient(MONGO_URI)
    db = client['Netflows']
    col = db['parse_netflow']
    col.update_many({'src_addr':ip},{'$set':{'attribution':True,'attribution_date':datetime.now(timezone.utc),'src_known':exclusion_status,'src_malicious':mal_status,'src_malicious_source':mal_src}})
    col.update_many({'dst_addr':ip},{'$set':{'attribution':True,'attribution_date':datetime.now(timezone.utc),'dst_known':exclusion_status,'dst_malicious':mal_status,'dst_malicious_source':mal_src}})
    client.close()
def get_non_enricheddata():
    client = MongoClient(MONGO_URI)
    db = client['Netflows']
    col = db['parse_netflow']
    pipeline = [
    {
        '$match': {
            'attribution': False
        }
    }, {
        '$addFields': {
            'ips': [
                '$src_addr', '$dst_addr'
            ]
        }
    }, {
        '$project': {
            'ips': 1,
            'ip_version':1
        }
    }, {
        '$unwind': '$ips'
    }, {
        '$group': {
            '_id': '$ips', 
            'count': {
                '$sum': 1
            },
            'ip_version':{'$last':'$ip_version'}
        }
    }
]
    jsondata = list(col.aggregate(pipeline))
    client.close()
    return jsondata
