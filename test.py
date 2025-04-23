# from test2 import print_context
# from context import app_context
# print_context()

# app_context.set_var("app_name", "api_module")
# print(app_context.app)

# from models import NetflowRawRecord
# print(NetflowRawRecord.source)

# from database import AppDB

# from context import context
# context.set_var("app_name", "API")
# AppDB().async_.NetflowUser.find_one()


# class MyDescriptor:
#     def __get__(self, instance, owner):
#         print(f"Accessed from {instance=} and {owner=}")
#         return 42

# class A():
#     m = MyDescriptor() 

# print(A().m)

from context import context
context.set_var("app_name", "API")

from http_api.auth import Auth
from globals_ import env

auth = Auth(secret=env.AUTH_SECRET, token_expiration_minutes=env.TOKEN_EXPIRATION_LIMIT)
print(auth.encode_password("8tVo0TwYhDoUTU8pvbZ79Zl0"))

