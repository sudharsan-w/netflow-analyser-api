from fastapi import APIRouter, Request, Response, HTTPException, Security, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from datetime import datetime

from database import AppDB
from globals_ import env
from ..auth import Auth
from ..models import Auth as AuthModel

security = HTTPBearer()
router = APIRouter(prefix=env.API_PREFIX)

auth_handler = Auth(
    secret=env.AUTH_SECRET, token_expiration_minutes=env.TOKEN_EXPIRATION_LIMIT
)


def role_based_jwt(*roles):
    if env.DEV:
        return lambda: "testuser"

    async def jwt_auth(
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ):
        token = credentials.credentials
        payload = auth_handler.decode_token(token)
        user = AppDB().get_collection(AppDB.NetFlowAPI.Users).find_one({"key": payload})
        if not payload or not user:
            raise HTTPException(
                status_code=403, detail="Invalid token or expired token."
            )
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="user role not allowed")
        return payload

    return jwt_auth


@router.post("/login", tags=["Auth"])
def login(user_details: AuthModel, request: Request, response: Response):
    user = (
        AppDB()
        .get_collection(AppDB.NetFlowAPI.Users)
        .find({"key": user_details.username})
    )
    user = list(user)[0]
    if user is None:
        return HTTPException(status_code=401, detail="Invalid username")
    if not auth_handler.verify_password(user_details.password, user["password"]):
        return HTTPException(status_code=401, detail="Invalid password")
    access_token, expiration_time = auth_handler.encode_token(user["key"])
    refresh_token = auth_handler.encode_refresh_token(user["key"])
    AppDB().get_collection(AppDB.NetFlowAPI.LoginSessions).insert_one(
        {
            "request_ip": request.headers.get("x-forwarded-for"),
            "request_datetime": datetime.now().astimezone(),
            "request_url": str(request.url),
            "request_headers": {
                i: request.headers.get(i) for i in request.headers.keys()
            },
            "request_cookies": request.cookies,
            "user_ref": user_details.username,
            "access_token": access_token,
            "refres_token": refresh_token,
        }
    )
    response.set_cookie(
        "rmtn",
        value=access_token,
        expires=expiration_time,
        secure=True,
        samesite="strict",
    )
    return {
        "role": user["role"],
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.get("/token", tags=["Auth"])
def login(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    try:
        user_key = auth_handler.decode_token(token)
        user_ = AppDB().get_collection(AppDB.NetFlowAPI.Users).find_one({"key": user_key})
        return {"username": user_key, "role": user_["role"], "valid": True}
    except:
        return {"valid": False}
