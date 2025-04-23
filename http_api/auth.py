import os
import pytz
import jwt
from fastapi import HTTPException
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone as dt_timezone


class Auth:
    hasher = CryptContext(schemes=["bcrypt"])
    """cat /dev/urandom | tr -dc 'a-zA-Z0-9()$%*' |fold -w 64  | head -n 1"""

    def __init__(self, token_expiration_minutes, secret) -> None:
        self.secret = secret
        self.token_expiration_minutes = token_expiration_minutes

    def encode_password(self, password):
        return self.hasher.hash(password)

    def verify_password(self, password, encoded_password):
        return self.hasher.verify(password, encoded_password)

    def encode_token(self, username):
        expiration_time = datetime.now().astimezone(dt_timezone.utc) + timedelta(
            minutes=self.token_expiration_minutes
        )
        payload = {
            "exp": expiration_time,
            "iat": datetime.now().astimezone(dt_timezone.utc),
            "scope": "access_token",
            "sub": username,
        }
        return jwt.encode(payload, self.secret, algorithm="HS256"), expiration_time

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=["HS256"])
            # decoded_token = jwt.decode(token, self.secret, algorithms=["HS256"], options={"verify_signature": False})
            # exp_timestamp = decoded_token.get('exp')
            # expiration_time = datetime.utcfromtimestamp(exp_timestamp)
            # if expiration_time.astimezone() > (datetime.now()+ timedelta(minutes=self.token_expiration_minutes)).astimezone(pytz.timezone('utc')):
            #     raise jwt.ExpiredSignatureError('Token Expired')
            if payload["scope"] == "access_token":
                return payload["sub"]
            raise HTTPException(
                status_code=401, detail="Scope for the token is invalid"
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid token")

    def encode_refresh_token(self, username):
        payload = {
            "exp": datetime.utcnow() + timedelta(days=0, hours=10),
            "iat": datetime.utcnow(),
            "scope": "refresh_token",
            "sub": username,
        }
        return jwt.encode(payload, self.secret, algorithm="HS256")

    def refresh_token(self, refresh_token):
        try:
            payload = jwt.decode(refresh_token, self.secret, algorithms=["HS256"])
            if payload["scope"] == "refresh_token":
                username = payload["sub"]
                new_token, _ = self.encode_token(username)
                return new_token
            raise HTTPException(status_code=401, detail="Invalid scope for token")
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Refresh token expired")
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail="Invalid refresh token")


if __name__ == "__main__":
    p = Auth().encode_password(password="AttpQ1Xg(*q87+G9WWh")
    print(p)
