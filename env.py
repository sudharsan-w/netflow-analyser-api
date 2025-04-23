from os import path
from pydantic_settings import BaseSettings

from context import context

env_path = path.join(path.dirname(__file__), '.env')


class DefaultEnv(BaseSettings):
    APP_MONGO_URL: str
    APP_DB_NAME: str
    DEFAULT_TIME_ZONE: str
    class Config:
        env_file = env_path
        env_file_encoding = "utf-8"


if context.app == "API":
    class Env(DefaultEnv):
        DEV: bool
        API_KEY: str
        API_PREFIX: str
        TOKEN_EXPIRATION_LIMIT: int
        AUTH_SECRET: str
        FILES_DIR: str


if context.app == "FLOW":
    class Env(DefaultEnv):
        pass

