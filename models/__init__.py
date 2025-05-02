from pytz import timezone
from typing import Optional, Literal, List, Union
from datetime import datetime
from pydantic import BaseModel, Field

import uuid

SortOrder = Literal["asc", "desc"]
TimeGranularity = Literal["day", "hour", "minute"]


class NetflowRecord(BaseModel):
    source: str  # probably file name
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
    record_num: Optional[int]
    flow_size: int
    in_byte: int
    in_packet: int
    protocol: str
    tcp_flag: str
    ip_version: str
    rr_id: str
    attribution: bool
    attribution_date: Optional[datetime] = None
    src_known: Optional[bool] = (
        None  # exclusions applied and then we only process false
    )
    src_malicious: Optional[bool] = (
        None  # mapped after the malicious nature of the dest port
    )
    src_malicious_source: Optional[dict] = None
    dst_known: Optional[bool] = (
        None  # exclusions applied and then we only process false
    )
    dst_malicious: Optional[bool] = (
        None  # mapped after the malicious nature of the dest port
    )
    dst_malicious_source: Optional[dict] = None
    src_country_code: Optional[str] = None
    dst_country_code: Optional[str] = None


class NetflowRawRecord(BaseModel):
    source: str
    data: dict
    netflow_version: int
    rr_id: str = Field(default_factory=lambda: str(uuid.uuid4()))


class UserNetflow(BaseModel):
    usr_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    date_added: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    date_updated: Optional[datetime] = None
    src_connection_count: int
    dst_connection_count: int
    malicious_count: Optional[int] = (
        None  # malicious connection counts based on dst or src
    )
    ip: str
    ip_version: str
    asn: Optional[str] = None
    geo_location: Optional[dict] = None
    malicious_crefs: Optional[list] = None  # flow refs
    schema_version: int = Field(default=1)
    country_code: Optional[str] = None

class NetflowAlert(BaseModel):
    class Malicious(BaseModel):
        source: str
        type_: Optional[Union[str, None]] = None
        date: Optional[datetime] = None

    src_ip: str
    src_ip_version: str
    src_port: str
    src_asn: str
    src_country_code: Optional[str] = None
    src_malicious_meta: List[Malicious]
    dst_ip: str
    dst_ip_version: str
    dst_port: str
    dst_asn: str
    dst_country_code: Optional[str] = None
    dst_malicious_meta: List[Malicious]
    connection_counts: int
    total_flow_duration: int
    first_seen: datetime
    last_seen: datetime
    mitigation_message: Optional[str] = ""
    alerts: Optional[dict] = None

# =================================


class EndpointInfo(BaseModel):
    addr: str
    port: Optional[Union[str, None]] = None
    known: Optional[bool] = None
    malicious: Optional[Union[bool, None]] = None
    malicious_source: Optional[Union[dict, None]] = None
    asn: Optional[str] = None
    location: Optional[dict] = None


class ParsedNetflow(BaseModel):
    source: str  # probably file name
    date_added: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    record_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    schema_version: int = Field(default=1)
    netflow_version: int
    source_ip: EndpointInfo
    destination_ip: EndpointInfo
    first_datetime: datetime
    last_datetime: datetime
    flow_duration: int
    collected_recv_datetime: datetime
    record_num: Optional[int]
    flow_size: int
    in_byte: int
    in_packet: int
    protocol: int
    tcp_flag: str
    ip_version: str
    rr_id: str
    attribution: bool
    attribution_date: Optional[datetime] = None


# ================================================


class ExcludedInfo(BaseModel):
    is_excluded: bool
    excluded_on: Optional[datetime] = None
    matched_range_ref: Optional[str] = None


class User(BaseModel):
    usr_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    date_added: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    date_updated: Optional[datetime] = None
    src_connection_count: int
    dst_connection_count: int
    malicious_count: Optional[int] = (
        None  # malicious connection counts based on dst or src
    )
    ip: str
    ip_version: str
    asn: Optional[str] = None
    geo_location: Optional[dict] = None
    malicous_crefs: Optional[list] = None  # flow refs
    schema_version: int = Field(default=1)
    excluded: Optional[ExcludedInfo] = None

# ====================================================


class MaliciousMeta(BaseModel):
    source: str
    type_: Optional[Union[str, None]] = None
    date: Optional[datetime] = None


class Endpoint(BaseModel):
    ip: str
    ip_version: str
    port: str
    asn: str
    location: Optional[dict]
    malicious_meta: List[MaliciousMeta]


class Alert(BaseModel):
    source: Endpoint
    destination: Endpoint
    connection_counts: int
    total_flow_duration: int
    first_seen: datetime
    last_seen: datetime
    mitigation_message: Optional[str] = ""
    alerts: Optional[dict] = None
