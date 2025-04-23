from datetime import datetime, timedelta
from typing import Optional, Dict, Literal
from database import AppDB
from models import NetflowRecord, SortOrder

from utils import iterate_async

NetflowFields = tuple(NetflowRecord.model_fields.keys())
NetflowFieldLiteral = Literal[NetflowFields]


NETFLOW_PIPELINE = lambda: [
    {
        "$set": {
            "src_addr": "$source_ip.addr",
            "src_port": "$source_ip.port",
            "src_known": "$source_ip.known",
            "src_malicious": "$source_ip.malicious",
            "src_malicious_source": "$source_ip.malicious_source",
            "dst_addr": "$destination_ip.addr",
            "dst_port": "$destination_ip.port",
            "dst_known": "$destination_ip.known",
            "src_malicious": "$destination_ip.malicious",
            "src_malicious_source": "$destination_ip.malicious_source",
        }
    }
]


async def get_netflow(
    skip: Optional[int] = None,
    limit: Optional[int] = None,
    filters: Dict[NetflowFieldLiteral, list] = {},
    search_key: Optional[str] = None,
    flow_duration_lb: Optional[float] = None,
    flow_duration_ub: Optional[float] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    sort_by: Optional[NetflowFieldLiteral] = None,
    sort_order: SortOrder = "asc",
):
    pipeline = [*NETFLOW_PIPELINE()]

    ##filters
    if filters:
        if "src_port" in filters:
            filters["src_port"] = [int(i) for i in filters["src_port"]]
        if "dst_port" in filters:
            filters["dst_port"] = [int(i) for i in filters["dst_port"]]
        if "protocol" in filters:
            filters["protocol"] = [int(i) for i in filters["protocol"]]
        for k, v in filters.items():
            pipeline.append({"$match": {k: {"$in": v}}})

    ##search key
    if search_key:
        search_key = search_key.strip()
        ip, port = None, None
        if ":" in search_key:
            ip, port = search_key.split(":")
        else:
            ip = search_key
        or_ = []
        if ip:
            or_.extend(
                [
                    {"src_addr": {"$regex": ip}},
                    {"dst_addr": {"$regex": ip}},
                ]
            )
        if port:
            or_.extend(
                [
                    {"src_port": {"$regex": port}},
                    {"dst_port": {"$regex": port}},
                ]
            )
        pipeline.append({"$match": {"$or": or_}})

    ##flow duration
    if flow_duration_ub or flow_duration_lb:
        pipeline.insert(
            0,
            {
                "$set": {
                    "flow_duration": {
                        "$dateDiff": {
                            "startDate": "$first_datetime",
                            "endDate": "$last_datetime",
                            "unit": "millisecond",
                        }
                    }
                }
            },
        )
        if flow_duration_lb and flow_duration_ub:
            pipeline.append(
                {
                    "$match": {
                        "flow_duration": {
                            "$gte": flow_duration_lb,
                            "$lte": flow_duration_ub,
                        }
                    }
                }
            )
        elif flow_duration_lb:
            pipeline.append(
                {
                    "$match": {
                        "flow_duration": {
                            "$gte": flow_duration_lb,
                        }
                    }
                }
            )
        elif flow_duration_ub:
            pipeline.append({"$match": {"flow_duration": {"$lte": flow_duration_ub}}})

    ##datefilters
    if date_from or date_to:
        date_to = (
            None if not date_to else date_to + timedelta(days=1) - timedelta(minutes=1)
        )
        date_from = None if not date_from else date_from
        if date_from and date_to:
            pipeline.insert(
                0, {"$match": {"first_datetime": {"$gte": date_from, "$lte": date_to}}}
            )
        elif date_from:
            pipeline.insert(0, {"$match": {"first_datetime": {"$gte": date_from}}})
        elif date_to:
            pipeline.insert(0, {"$match": {"first_datetime": {"$lte": date_to}}})

    if sort_by:
        pipeline.append({"$sort": {sort_by: -1 if sort_order == "desc" else 1}})

    if skip:
        pipeline.append({"$skip": skip})
    if limit:
        pipeline.append({"$limit": limit * 10.5})

    data = (
        AppDB()
        .get_collection(AppDB.NetFlows.ParsedNetflow, async_=True)
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
    data_slice = list(map(lambda a: NetflowRecord(**a), data_slice))

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


async def get_proro_keys():
    keys = (
        AppDB()
        .get_collection(AppDB.NetFlows.ParsedNetflow, async_=True)
        .aggregate([{"$group": {"_id": "", "keys": {"$addToSet": "$protocol"}}}])
    )
    keys = await iterate_async(keys)
    if len(keys) == 0:
        return []
    keys = list(map(str, keys[0]["keys"]))
    return keys


async def get_srcports_keys():
    keys = (
        AppDB()
        .get_collection(AppDB.NetFlows.ParsedNetflow, async_=True)
        .aggregate(
            [
                # {"$group": {"_id": "", "keys": {"$addToSet": "$src_port"}}},
                {"$group": {"_id": "", "keys": {"$addToSet": "$source_ip.port"}}},
            ]
        )
    )
    keys = await iterate_async(keys)
    if len(keys) == 0:
        return []
    keys = list(map(str, keys[0]["keys"]))
    return list(filter(lambda k: len(k) <= 5, keys))


async def get_dstports_keys():
    keys = (
        AppDB()
        .get_collection(AppDB.NetFlows.ParsedNetflow, async_=True)
        .aggregate(
            [
                # {"$group": {"_id": "", "keys": {"$addToSet": "$dst_port"}}},
                {"$group": {"_id": "", "keys": {"$addToSet": "$destination_ip.port"}}},
            ]
        )
    )
    keys = await iterate_async(keys)
    if len(keys) == 0:
        return []
    keys = list(map(str, keys[0]["keys"]))
    return list(filter(lambda k: len(k) <= 5, keys))
