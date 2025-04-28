from datetime import datetime, timedelta
from typing import Optional, Dict, Literal
from database import AppDB
from models import NetflowRecord, ParsedNetflow, SortOrder

from utils import iterate_async, proto

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
            "src_country_code": "$source_ip.location.iso_code",
        }
    }
]


_FIELDS = {
    "src_addr": "source_ip.addr",
    "src_port": "source_ip.port",
    "src_known": "source_ip.known",
    "src_malicious": "source_ip.malicious",
    "src_malicious_source": "source_ip.malicious_source",
    "src_country_code": "source_ip.location.iso_code",
}


def _field_name(f, mongovar=False):
    if mongovar:
        return f"${_FIELDS.get(f, f)}"
    return _FIELDS.get(f, f)


def _rev_projection():
    return {_field_name(k): f"${k}" for k in _FIELDS}


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
    # pipeline = []

    ##filters
    if filters:
        if "protocol" in filters:
            filters["protocol"] = [
                proto.l4_proto_reverse(i) for i in filters["protocol"]
            ]
        for k, v in filters.items():
            pipeline.append({"$match": {_field_name(k): {"$in": v}}})

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
                    {_field_name("src_addr"): {"$regex": ip}},
                ]
            )
        if port:
            or_.extend(
                [
                    {_field_name("src_port"): {"$regex": port}},
                ]
            )
        pipeline.append({"$match": {"$or": or_}})

    ##flow duration
    if flow_duration_ub or flow_duration_lb:
        # pipeline.insert(
        #     0,
        #     {
        #         "$set": {
        #             "flow_duration": {
        #                 "$dateDiff": {
        #                     "startDate": _field_name("first_datetime", True),
        #                     "endDate": _field_name("last_datetime", True),
        #                     "unit": "millisecond",
        #                 }
        #             }
        #         }
        #     },
        # )
        if flow_duration_lb and flow_duration_ub:
            pipeline.append(
                {
                    "$match": {
                        _field_name("flow_duration"): {
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
                        _field_name("flow_duration"): {
                            "$gte": flow_duration_lb,
                        }
                    }
                }
            )
        elif flow_duration_ub:
            pipeline.append(
                {"$match": {_field_name("flow_duration"): {"$lte": flow_duration_ub}}}
            )

    ##datefilters
    if date_from or date_to:
        date_to = (
            None if not date_to else date_to + timedelta(days=1) - timedelta(minutes=1)
        )
        date_from = None if not date_from else date_from
        if date_from and date_to:
            pipeline.insert(
                0,
                {
                    "$match": {
                        _field_name("first_datetime"): {
                            "$gte": date_from,
                            "$lte": date_to,
                        }
                    }
                },
            )
        elif date_from:
            pipeline.insert(
                0, {"$match": {_field_name("first_datetime"): {"$gte": date_from}}}
            )
        elif date_to:
            pipeline.insert(
                0, {"$match": {_field_name("first_datetime"): {"$lte": date_to}}}
            )

    if sort_by:
        pipeline.append(
            {"$sort": {_field_name(sort_by): -1 if sort_order == "desc" else 1}}
        )

    if skip:
        pipeline.append({"$skip": skip})
    if limit:
        pipeline.append({"$limit": limit * 10.5})

    # pipeline.append({"$set": _rev_projection()})

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
    data_slice = list(map(lambda a: ParsedNetflow(**a), data_slice))
    parsed_data_slice = []
    for d in data_slice:
        parsed = NetflowRecord(
            src_addr=d.source_ip.addr,
            src_port=d.source_ip.port,
            src_known=d.source_ip.known,
            src_malicious=d.source_ip.malicious,
            src_malicious_source=d.source_ip.malicious_source,
            src_country_code=d.source_ip.location.get("iso_code"),
            dst_addr=d.destination_ip.addr,
            dst_port=d.destination_ip.port,
            dst_known=d.destination_ip.known,
            dst_malicious=d.destination_ip.malicious,
            dst_malicious_source=d.destination_ip.malicious_source,
            dst_country_code=d.destination_ip.location.get("iso_code"),
            protocol=(
                proto.l4_proto(d.protocol)
                if proto.l4_proto(d.protocol)
                else str(d.protocol)
            ),
            source=d.source,
            date_added=d.date_added,
            record_id=d.record_id,
            schema_version=d.schema_version,
            netflow_version=d.netflow_version,
            first_datetime=d.first_datetime,
            last_datetime=d.last_datetime,
            flow_duration=d.flow_duration,
            collected_recv_datetime=d.collected_recv_datetime,
            record_num=d.record_num,
            flow_size=d.flow_size,
            in_byte=d.in_byte,
            in_packet=d.in_packet,
            tcp_flag=d.tcp_flag,
            ip_version=d.ip_version,
            rr_id=d.rr_id,
            attribution=d.attribution,
            attribution_date=d.attribution_date,
        )
        parsed_data_slice.append(parsed)
    res = {
        "page_no": curr_page,
        "skip": skip,
        "limit": limit,
        "pages_till": pages_till,
        "has_next_pages": has_next_pages,
        "has_prev_pages": has_prev_pages,
        "data": parsed_data_slice,
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
    keys = list(
        map(
            lambda p: proto.l4_proto(p) if proto.l4_proto(p) else f"{p}",
            keys[0]["keys"],
        )
    )
    return sorted(keys)


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
    return sorted(list(filter(lambda k: len(k) <= 5, keys)))


async def get_dstports_keys():
    keys = (
        AppDB()
        .get_collection(AppDB.NetFlows.ParsedNetflow, async_=True)
        .aggregate(
            [
                {"$group": {"_id": "", "keys": {"$addToSet": "$destination_ip.port"}}},
            ]
        )
    )
    keys = await iterate_async(keys)
    if len(keys) == 0:
        return []
    keys = list(map(str, keys[0]["keys"]))
    return sorted(list(filter(lambda k: len(k) <= 5, keys)))


async def get_srccountries_keys():
    keys = (
        AppDB()
        .get_collection(AppDB.NetFlows.ParsedNetflow, async_=True)
        .aggregate(
            [
                {
                    "$group": {
                        "_id": "",
                        "keys": {"$addToSet": "$source_ip.location.iso_code"},
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


async def get_dstcountries_keys():
    keys = (
        AppDB()
        .get_collection(AppDB.NetFlows.ParsedNetflow, async_=True)
        .aggregate(
            [
                {
                    "$group": {
                        "_id": "",
                        "keys": {"$addToSet": "$destination_ip.location.iso_code"},
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

async def get_srcasn_keys():
    keys = (
        AppDB()
        .get_collection(AppDB.NetFlows.ParsedNetflow, async_=True)
        .aggregate(
            [
                {
                    "$group": {
                        "_id": "",
                        "keys": {"$addToSet": "$source_ip.asn"},
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

async def get_dstasn_keys():
    keys = (
        AppDB()
        .get_collection(AppDB.NetFlows.ParsedNetflow, async_=True)
        .aggregate(
            [
                {
                    "$group": {
                        "_id": "",
                        "keys": {"$addToSet": "$destination_ip.asn"},
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
