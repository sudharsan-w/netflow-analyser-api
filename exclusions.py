from pydantic import BaseModel,Field
from typing import Optional
from pymongo import MongoClient,UpdateOne
from datetime import datetime, timezone
import uuid
import ipaddress
MONGO_URI = 'mongodb://localhost:27017/'
class Exclusion(BaseModel):
    name: str
    meta: Optional[dict] = None
    date_added: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str
    status_history: list
    ex_class: str
    ex_type: str #ipv4 or v6
    ex_entity:str
    added_by: str
    ex_id: str = Field(default_factory=lambda : str(uuid.uuid4()))
def bulk_insert_exclusions(list_events: list[Exclusion]):
    client = MongoClient(MONGO_URI)
    db = client['Exclusions']
    col = db['exclusion']
    bulk_ops = []
    for js in list_events:
        jsondata = js.dict()
        condition = {
                'ex_type':jsondata['ex_type'],
                'ex_entity':jsondata['ex_entity']
        }
        bulk_ops.append(
            UpdateOne(
                filter=condition,          # Condition for existence check
                update={'$setOnInsert': jsondata},  # Inserts document only if condition isn't met
                upsert=True
            )
        )
    result = col.bulk_write(bulk_ops)
    client.close()
    print(f"Inserted Count: {len(result.upserted_ids)}")
    print(f"Matched (existing): {result.matched_count}")
def insert_exclusion(ex: Exclusion):
    client = MongoClient(MONGO_URI)
    db = client['Exclusions']
    col = db['exclusion']
    jj = col.find_one({'ex_type':ex.ex_type,'ex_entity':ex.ex_entity})
    if not jj:
        col.insert_one(ex.dict())
    client.close()
def get_exclusions(ex_type):
    client = MongoClient(MONGO_URI)
    db = client['Exclusions']
    col = db['exclusion']
    jsondata = list(col.find({'status':'ON','ex_type':ex_type}))
    client.close()
    return jsondata
def check_entity(entity,entity_type,ex_type,ex_entity):
    if ex_type == 'IPV4' and entity_type=='IPV4':
        network = ipaddress.IPv4Network(ex_entity, strict=False)
        return ipaddress.IPv4Address(entity) in network
    elif ex_type == 'IPV6' and entity_type=='IPV6':
        network = ipaddress.IPv6Network(ex_entity, strict=False)
        return ipaddress.IPv6Address(entity) in network
def check_all_ex(entity,entity_type):
    all_ex = get_exclusions(entity_type)
    exclude = False
    t_f= []
    for i in all_ex:
        t_f.append(check_entity(entity,entity_type,i['ex_type'],i['ex_entity']))
    if True in t_f:
        exclude = True
    return exclude
print(check_all_ex('1.1.1.1',entity_type='IPV4'))
