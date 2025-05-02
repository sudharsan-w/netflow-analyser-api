import asyncio
from typing import Optional, Dict, Literal
from datetime import datetime, timedelta

from database import AppDB
from utils.async_ import iterate_async
from models import SortOrder, NetflowAlert

ALERT_PIPELINE = lambda:[
    {
        "$set": {
            "src_ip": "$source.ip",
            "src_ip_version": "$source.ip_version",
            "src_port": "$source.port",
            "src_asn": "$source.asn",
            "src_country_code": "$source.location.iso_code",
            "src_malicious_meta": "$source.malicious_meta",
            "dst_ip": "$destination.ip",
            "dst_ip_version": "$destination.ip_version",
            "dst_port": "$destination.port",
            "dst_asn": "$destination.asn",
            "dst_country_code": "$destination.location.iso_code",
            "dst_malicious_meta": "$destination.malicious_meta",
        }
    }
]

AlertFields = tuple(NetflowAlert.model_fields.keys())
AlertFieldLiteral = Literal[AlertFields]

async def get_alerts(
    skip: Optional[int] = None,
    limit: Optional[int] = None,
    filters: Dict[AlertFieldLiteral, list] = {},
    search_key: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    sort_by: Optional[AlertFieldLiteral] = None,
    sort_order: SortOrder = "asc",
):
    pipeline = [*ALERT_PIPELINE()]

    ##filters
    if filters:
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
                    {"src_ip": {"$regex": ip}},
                    {"dst_ip": {"$regex": ip}},
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


    ##datefilters
    if date_from or date_to:
        date_to = (
            None if not date_to else date_to + timedelta(days=1) - timedelta(minutes=1)
        )
        date_from = None if not date_from else date_from
        if date_from and date_to:
            pipeline.insert(
                0, {"$match": {"last_seen": {"$gte": date_from, "$lte": date_to}}}
            )
        elif date_from:
            pipeline.insert(0, {"$match": {"last_seen": {"$gte": date_from}}})
        elif date_to:
            pipeline.insert(0, {"$match": {"last_seen": {"$lte": date_to}}})

    pagination = []
    if sort_by:
        pagination.append({"$sort": {sort_by: -1 if sort_order == "desc" else 1}})

    if skip:
        pagination.append({"$skip": skip})
    if limit:
        pagination.append({"$limit": limit * 10.5})

    data = (
        AppDB()
        .get_collection(AppDB.NetFlows.Alerts, async_=True)
        .aggregate(pipeline+pagination)
    )
    agg = (
        AppDB()
        .get_collection(AppDB.NetFlows.Alerts, async_=True)
        .aggregate(pipeline+[{"$count": "total"}])
    )
    data, agg = await asyncio.gather(iterate_async(data), iterate_async(agg))


    if len(data) > 0 and len(agg) > 0:
        total_results = agg[0]["total"]
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
        total_results = 0
        curr_page = int(skip / limit)
        pages_till = 0
        has_next_pages = False
        has_prev_pages = False
    data_slice = data[0 : min(limit, len(data))]
    data_slice = list(map(lambda a: NetflowAlert(**a), data_slice))

    res = {
        "page_no": curr_page,
        "skip": skip,
        "limit": limit,
        "total_results": total_results,
        "pages_till": pages_till,
        "has_next_pages": has_next_pages,
        "has_prev_pages": has_prev_pages,
        "data": data_slice,
    }
    return res
