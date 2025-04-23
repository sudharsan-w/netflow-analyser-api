from utils import *
from enrichment import *
from integrations import *
from exclusions import check_all_ex
jsondata = get_non_enricheddata()
print(jsondata)
non_known=[]
for i in jsondata:
    if not check_all_ex(i['_id'],entity_type=f'IPV{i["ip_version"]}'):
        non_known.append(i)
    else:
        update_many_flows(i['_id'],exclusion_status=True,mal_status=None,mal_src=None)
for i in non_known:
    info = get_entity_info(i['_id'],entity_type=f'IPV{i["ip_version"]}') 
    print(info)


