import re
import json
import uuid
from ipaddress import IPv4Address, IPv4Network, IPv6Address, IPv6Network
from bson import ObjectId
from datetime import datetime
from enum import Enum
from pytz import timezone
from pydantic import BaseModel

from .async_ import *

from globals_ import env

ID = lambda: str(uuid.uuid4())


def to_utc(dt_obj: datetime, tz=env.DEFAULT_TIME_ZONE):
    if dt_obj.tzinfo == None:
        dt_obj = tz.localize(dt=dt_obj)
    return dt_obj.astimezone(timezone("UTC"))


def to_tz(dt_obj: datetime, to_tz, curr_tz=env.DEFAULT_TIME_ZONE):
    if dt_obj.tzinfo == None:
        dt_obj = curr_tz.localize(dt=dt_obj)
    return dt_obj.astimezone(to_tz)


def curr_time():
    return to_utc(datetime.now().astimezone())


def date_from_datetime(date_obj: datetime):
    return date_obj.replace(hour=0, minute=0, second=0, microsecond=0)


def extract_url_domain(s):
    s = s.replace("http://", "")
    s = s.replace("https://", "")
    s = s if not s.startswith("www.") else s[4:]
    s = s if not "/" in s else s[: s.index("/")]
    s = s if not "?" in s else s[: s.index("?")]
    s = s.replace('"', "")
    return s



def mongo_serializer(obj):
    func_ = mongo_serializer
    if (
        isinstance(obj, IPv4Address)
        or isinstance(obj, IPv4Network)
        or isinstance(obj, IPv6Address)
        or isinstance(obj, IPv6Network)
    ):
        return str(obj)
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, datetime):
        return to_utc(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, BaseModel):
        return func_(vars(obj))
    if isinstance(obj, list):
        return [func_(e) for e in obj]
    if isinstance(obj, dict):
        return {func_(k): func_(v) for k, v in obj.items()}
    return obj


def json_serializer(obj):
    func_ = json_serializer
    if (
        isinstance(obj, IPv4Address)
        or isinstance(obj, IPv4Network)
        or isinstance(obj, IPv6Address)
        or isinstance(obj, IPv6Network)
    ):
        return str(obj)
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, BaseModel):
        return func_(vars(obj))
    if isinstance(obj, list):
        return [func_(e) for e in obj]
    if isinstance(obj, dict):
        return {func_(k): func_(v) for k, v in obj.items()}
    return obj


def csv_serializer(obj):
    func_ = csv_serializer
    if (
        isinstance(obj, IPv4Address)
        or isinstance(obj, IPv4Network)
        or isinstance(obj, IPv6Address)
        or isinstance(obj, IPv6Network)
    ):
        return str(obj)
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, ObjectId):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, BaseModel):
        return func_(vars(obj))
    if isinstance(obj, list):
        return ", ".join([func_(e) for e in obj])
    if isinstance(obj, dict):
        return json.dumps({func_(k): func_(v) for k, v in obj.items()})
    return obj


def timezone_updater(obj, tz):
    func_ = timezone_updater
    if isinstance(obj, datetime):
        return to_tz(obj, tz)
    elif isinstance(obj, list):
        return [func_(e, tz) for e in obj]
    elif isinstance(obj, dict):
        for k, v in obj.items():
            obj[k] = func_(v, tz)
    elif isinstance(obj, BaseModel):
        for k, v in obj.dict().items():
            obj.__setattr__(k, func_(v, tz))
    return obj


def is_valid_vpa(txt):
    pattern = r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$"
    matched = re.match(pattern, txt)
    return matched


def if_null(*args):
    for arg in args:
        if not arg:
            return arg

def mongo_date_format(granularity):
    if granularity == "day":
        return "%Y-%m-%d"
    if granularity == "hour":
        return "%Y-%m-%dT%H"
    if granularity == "minute":
        return "%Y-%m-%dT%H:%M"
    return "%Y-%m-%dT%H:%M:%S"
