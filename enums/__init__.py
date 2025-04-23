import pytz
from enum import Enum

TimeZoneEnum = Enum(
    "TimeZoneEnum",
    {tz.replace("/", "_").replace("-", "_").upper(): tz for tz in pytz.all_timezones},
)
