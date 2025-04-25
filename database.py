from bson.codec_options import CodecOptions
from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient

from globals_ import env

codec_options = CodecOptions(tz_aware=True)


class classproperty(object):
    def __init__(self, f):
        self.f = f

    def __get__(self, obj, owner):
        return self.f(owner)


class SyncClient(MongoClient):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __del__(self):
        try:
            self.close()
        except ImportError:
            pass


class SyncDBConnection(SyncClient):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, *args, **kwargs):
        if not hasattr(self, "_app_initialized"):
            super().__init__(*args, **kwargs)
            self._app_initialized = True


class AsyncDBConnection(AsyncIOMotorClient):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, *args, **kwargs):
        if not hasattr(self, "_app_initialized"):
            super().__init__(*args, **kwargs)
            self._app_initialized = True


class DB:
    sync_: SyncDBConnection
    async_: AsyncDBConnection
    __db_url__: str

    class NameSpace:
        db: str
        coll: str

        def __init__(self, db, coll):
            self.db = db
            self.coll = coll

        @property
        def full_name(self):
            return f"{self.db}.{self.coll}"

    class Database:
        __name: str
        namespace: "DB.NameSpace"

        @classmethod
        @classproperty
        def name(cls):
            return cls.__name

        @classmethod
        @classproperty
        def namespace(cls) -> "DB.NameSpace":
            return DB.NameSpace(cls.name, None)

    class Collection:
        __name: str

        def __init__(self, name):
            self.__name = name

        def __get__(self, _, owner):
            if not issubclass(owner, DB.Database):
                raise Exception("Collection object only be used inside")
            return DB.NameSpace(owner.namespace.db, self.__name)

    def __init__(self):
        self.sync_ = SyncDBConnection(self.__db_url__)
        self.async_ = AsyncDBConnection(self.__db_url__)

    def get_collection(self, namespace: NameSpace, async_: bool = False):

        if async_:
            cli = self.async_
        else:
            cli = self.sync_
        return cli.get_database(
            namespace.db, codec_options=codec_options
        ).get_collection(namespace.coll)

    def get_database(self, database: Database, async_: bool = False):

        if async_:
            cli = self.async_
        else:
            cli = self.sync_

        return cli.get_database(database.namespace.db, codec_options=codec_options)


class AppDB(DB):

    __db_url__ = env.APP_MONGO_URL

    class NetFlows(DB.Database):
        _Database__name = "netflow"

        ParsedNetflow = DB.Collection("parsed_netflow")
        RawNetflow = DB.Collection("row_netflow")
        NetflowUser = DB.Collection("users")
        Alerts = DB.Collection("alerts")

    class NetFlowAPI(DB.Database):
        _Database__name = "netflow_api"

        Users = DB.Collection("users")
        LoginSessions = DB.Collection("login_sessions")


# class ApiDB(DB):

#     __db_url__ = env.APP_MONGO_URL

#     class NetFlows(DB.Database):
#         _Database__name = "netflow_api"

#         Users = DB.Collection("users")
#         LoginSessions = DB.Collection("login_sessions")

