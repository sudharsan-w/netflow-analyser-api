from datetime import datetime, timedelta
from typing import Optional, Dict, Literal
from database import AppDB
from models import NetflowRecord, SortOrder, UserNetflow

from utils import iterate_async

NetflowFields = tuple(UserNetflow.model_fields.keys())
NetflowFieldLiteral = Literal[NetflowFields]

NETFLOWUSER_PIPELINE = lambda: [{"$set": {"country_code": "$geo_location.iso_code"}}]


async def get_netflow_user(
    skip: Optional[int] = None,
    limit: Optional[int] = None,
    filters: Dict[NetflowFieldLiteral, list] = {},
    search_key: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    sort_by: Optional[NetflowFieldLiteral] = None,
    sort_order: SortOrder = "asc",
):
    pipeline = [*NETFLOWUSER_PIPELINE()]

    ##filters
    if filters:
        for k, v in filters.items():
            pipeline.append({"$match": {k: {"$in": v}}})

    if search_key:
        search_key = search_key.strip()
        pipeline.append({"$match": {"ip": {"$regex": search_key}}})

    ##datefilters
    if date_from or date_to:
        date_to = (
            None if not date_to else date_to + timedelta(days=1) - timedelta(minutes=1)
        )
        date_from = None if not date_from else date_from
        if date_from and date_to:
            pipeline.insert(
                0, {"$match": {"date_added": {"$gte": date_from, "$lte": date_to}}}
            )
        elif date_from:
            pipeline.insert(0, {"$match": {"date_added": {"$gte": date_from}}})
        elif date_to:
            pipeline.insert(0, {"$match": {"date_added": {"$lte": date_to}}})

    if sort_by:
        pipeline.append({"$sort": {sort_by: -1 if sort_order == "desc" else 1}})

    if skip:
        pipeline.append({"$skip": skip})
    if limit:
        pipeline.append({"$limit": limit * 10.5})

    data = (
        AppDB()
        .get_collection(AppDB.NetFlows.NetflowUser, async_=True)
        .aggregate(pipeline)
    )
    data = await iterate_async(data)

    if len(data) > 0:
        curr_page = int(skip / limit) + 1
        if len(data) > limit:
            pages_till = int((len(data) - limit) / limit) + curr_page
            has_next_pages = len(data) > limit * 10
            has_prev_pages = skip > 0
        else:
            pages_till = curr_page
            has_next_pages = False
            has_prev_pages = skip > 0
    else:
        curr_page = int(skip / limit)
        pages_till = 0
        has_next_pages = False
        has_prev_pages = False
    data_slice = data[0 : min(limit, len(data))]
    data_slice = list(map(lambda u: UserNetflow(**u), data_slice))
    res = {
        "page_no": curr_page,
        "skip": skip,
        "limit": limit,
        "pages_till": pages_till,
        "has_next_pages": has_next_pages,
        "has_prev_pages": has_prev_pages,
        "data": data_slice,
    }
    return res


async def get_user_details(id: str):

    user = (
        await AppDB()
        .get_collection(AppDB.NetFlows.NetflowUser, async_=True)
        .find_one({"usr_id": id}, {"_id": 0})
    )
    pipeline = [{"$set": {"flow_duration": {"$dateDiff": {"startDate": ""}}}}]

    return user


async def get_country_keys():
    keys = (
        AppDB()
        .get_collection(AppDB.NetFlows.NetflowUser, async_=True)
        .aggregate(
            [
                # {"$group": {"_id": "", "keys": {"$addToSet": "$dst_port"}}},
                {
                    "$group": {
                        "_id": "",
                        "keys": {"$addToSet": "$geo_location.iso_code"},
                    }
                },
            ]
        )
    )
    keys = await iterate_async(keys)
    if len(keys) == 0:
        return []
    keys = list(map(str, keys[0]["keys"]))
    return sorted(list(filter(lambda k: k, keys)))

async def get_asn_keys():
    keys = (
        AppDB()
        .get_collection(AppDB.NetFlows.NetflowUser, async_=True)
        .aggregate(
            [
                {
                    "$group": {
                        "_id": "",
                        "keys": {"$addToSet": "$asn"},
                    }
                },
            ]
        )
    )
    keys = await iterate_async(keys)
    if len(keys) == 0:
        return []
    keys = list(map(str, keys[0]["keys"]))
    return sorted(list(filter(lambda k: k, keys)))
