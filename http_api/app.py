from context import app_context

app_context.set_var("app_name", "API")

from typing import Union, Dict, Optional
from pytz import timezone
from datetime import datetime
from fastapi import FastAPI, APIRouter, Depends
from fastapi.middleware.cors import CORSMiddleware

from globals_ import env
from enums import TimeZoneEnum
from core import netflow, netflow_user, netflow_alerts
from models import SortOrder, TimeGranularity
from utils import json_serializer, timezone_updater

from .routes.auth import router as auth_router, role_based_jwt
from .auth import Auth

http_api = FastAPI(
    docs_url=f"{env.API_PREFIX}/docs", openapi_url=f"{env.API_PREFIX}/openapi.json"
)

http_api.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

router = APIRouter(prefix=env.API_PREFIX)

auth_handler = Auth(
    secret=env.AUTH_SECRET, token_expiration_minutes=env.TOKEN_EXPIRATION_LIMIT
)


@router.get("/")
def root():
    return {"msg": "api is up"}


@router.post(
    "/v1/get/netflows",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _netflows(
    page: int,
    limit: int,
    filters: Dict[netflow.NetflowFieldLiteral, list] = {},  # type: ignore
    search_key: Optional[str] = None,
    flow_duration_lb: Optional[float] = None,
    flow_duration_ub: Optional[float] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    sort_by: Optional[netflow.NetflowFieldLiteral] = None,  # type: ignore
    sort_order: SortOrder = "asc",
    tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA,  # type: ignore
):
    return json_serializer(
        timezone_updater(
            await netflow.get_netflow(
                filters_=netflow.get_filters(
                    filters=filters,
                    search_key=search_key,
                    flow_duration_lb=flow_duration_lb,
                    flow_duration_ub=flow_duration_ub,
                    date_from=date_from,
                    date_to=date_to,
                    tz=tz,
                ),
                sort_=netflow.get_sort(
                    sort_by=sort_by,
                    sort_order=sort_order,
                ),
                skip=(page - 1) * limit,
                limit=limit,
            ),
            tz=timezone(tz.value),
        )
    )


@router.post(
    "/v1/get/netflow_users",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _netflow_users(
    page: int,
    limit: int,
    filters: Dict[netflow_user.NetflowFieldLiteral, list] = {},  # type: ignore
    search_key: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    sort_by: Optional[netflow_user.NetflowFieldLiteral] = None,  # type: ignore
    sort_order: SortOrder = "asc",
    tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA,  # type: ignore
):
    return json_serializer(
        timezone_updater(
            await netflow_user.get_netflow_user(
                skip=(page - 1) * limit,
                limit=limit,
                filters=filters,
                search_key=search_key,
                date_from=date_from,
                date_to=date_to,
                sort_by=sort_by,
                sort_order=sort_order,
            ),
            tz=timezone(tz.value),
        )
    )


@router.post(
    "/v1/get/netflow_alerts",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _netflow_alerts(
    page: int,
    limit: int,
    filters: Dict[netflow_alerts.AlertFieldLiteral, list] = {},  # type: ignore
    search_key: Optional[str] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    sort_by: Optional[netflow_alerts.AlertFieldLiteral] = None,  # type: ignore
    sort_order: SortOrder = "asc",
    tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA,  # type: ignore
):
    return json_serializer(
        timezone_updater(
            await netflow_alerts.get_alerts(
                skip=(page - 1) * limit,
                limit=limit,
                filters=filters,
                search_key=search_key,
                date_from=date_from,
                date_to=date_to,
                sort_by=sort_by,
                sort_order=sort_order,
            ),
            tz=timezone(tz.value),
        )
    )


@router.post(
    "/v1/get/proto_dist",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _proto_dist(
    filters: Dict[netflow.NetflowFieldLiteral, list] = {},  # type: ignore
    search_key: Optional[str] = None,
    flow_duration_lb: Optional[float] = None,
    flow_duration_ub: Optional[float] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA,  # type: ignore
):  # type: ignore
    return json_serializer(
        timezone_updater(
            await netflow.get_protocol_dist(
                filters=netflow.get_filters(
                    filters=filters,
                    search_key=search_key,
                    flow_duration_lb=flow_duration_lb,
                    flow_duration_ub=flow_duration_ub,
                    date_from=date_from,
                    date_to=date_to,
                    tz=tz,
                )
            ),
            tz=timezone(tz.value),
        )
    )


@router.post(
    "/v1/get/netflow_dist",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _proto_dist(
    filters: Dict[netflow.NetflowFieldLiteral, list] = {},  # type: ignore
    search_key: Optional[str] = None,
    flow_duration_lb: Optional[float] = None,
    flow_duration_ub: Optional[float] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA,  # type: ignore
    granularity: TimeGranularity = None,
):  # type: ignore
    return json_serializer(
        timezone_updater(
            await netflow.get_flow_dist(
                filters=netflow.get_filters(
                    filters=filters,
                    search_key=search_key,
                    flow_duration_lb=flow_duration_lb,
                    flow_duration_ub=flow_duration_ub,
                    date_from=date_from,
                    date_to=date_to,
                    tz=tz,
                ),
                granularity=granularity,
                tz=tz,
            ),
            tz=timezone(tz.value),
        )
    )


@router.get(
    "/v1/get/netflow_user/details",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _user_details(id: str, tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA):  # type: ignore
    return json_serializer(
        timezone_updater(await netflow_user.get_user_details(id), tz=timezone(tz.value))
    )


@router.get(
    "/v1/get/protocol/keys",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _proto_keys(tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA):  # type: ignore
    return json_serializer(
        timezone_updater(await netflow.get_proro_keys(), tz=timezone(tz.value))
    )


@router.get(
    "/v1/get/src_port/keys",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _dstport_keys(tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA):  # type: ignore
    return json_serializer(
        timezone_updater(await netflow.get_srcports_keys(), tz=timezone(tz.value))
    )


@router.get(
    "/v1/get/dst_port/keys",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _srcport_keys(tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA):  # type: ignore
    return json_serializer(
        timezone_updater(await netflow.get_dstports_keys(), tz=timezone(tz.value))
    )


@router.get(
    "/v1/get/src_country/keys",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _country_keys(tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA):  # type: ignore
    return json_serializer(
        timezone_updater(await netflow.get_srccountries_keys(), tz=timezone(tz.value))
    )


@router.get(
    "/v1/get/dst_country/keys",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _country_keys(tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA):  # type: ignore
    return json_serializer(
        timezone_updater(await netflow.get_dstcountries_keys(), tz=timezone(tz.value))
    )


@router.get(
    "/v1/get/user_country/keys",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _country_keys(tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA):  # type: ignore
    return json_serializer(
        timezone_updater(await netflow_user.get_country_keys(), tz=timezone(tz.value))
    )


@router.get(
    "/v1/get/dst_asn/keys",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _srcasn_keys(tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA):  # type: ignore
    return json_serializer(
        timezone_updater(await netflow.get_srcasn_keys(), tz=timezone(tz.value))
    )


@router.get(
    "/v1/get/src_asn/keys",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _dstasn_keys(tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA):  # type: ignore
    return json_serializer(
        timezone_updater(await netflow.get_dstasn_keys(), tz=timezone(tz.value))
    )


@router.get(
    "/v1/get/user_asn/keys",
    tags=["NETFLOW"],
    dependencies=[Depends(role_based_jwt("dashboard_client.admin"))],
)
async def _userasn_keys(tz: TimeZoneEnum = TimeZoneEnum.ASIA_KOLKATA):  # type: ignore
    return json_serializer(
        timezone_updater(await netflow_user.get_asn_keys(), tz=timezone(tz.value))
    )


http_api.include_router(auth_router)
http_api.include_router(router)
