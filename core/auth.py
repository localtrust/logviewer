import os
import time

import jwt
import requests
from sanic import redirect
from functools import wraps


def encode_bearer_token(access_token, refresh_token, expires_in):
    return jwt.encode({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "exp": time.time() + expires_in
    }, os.getenv("JWT_SECRET"), algorithm="HS256")


def decode_bearer_token(bearer_token):
    try:
        return jwt.decode(bearer_token, os.getenv("JWT_SECRET"), algorithms=["HS256"])
    except jwt.exceptions.DecodeError:
        return None


def protected(wrapped):
    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            bearer_token = request.cookies.get("bearer_token")
            if not bearer_token:
                return redirect("/auth/login")
            session_info = decode_bearer_token(bearer_token)

            if session_info is not None:
                if time.time() >= session_info["exp"]:
                    return redirect("/auth/login")
                elif session_info["exp"] - time.time() <= 60 * 60 * 24:
                    r = requests.post("https://discord.com/api/v10/oauth2/token", data={
                        "grant_type": "refresh_token",
                        "refresh_token": session_info["refresh_token"],
                        "redirect_uri": os.getenv("AUTH_REDIRECT_URI"),
                    }, auth=(os.getenv("CLIENT_ID"), os.getenv("CLIENT_SECRET")))
                    if r.status_code == 401:
                        return redirect("/auth/login")
                    r = r.json()

                    response = redirect("/")
                    bearer_token = encode_bearer_token(
                        r["access_token"], r["refresh_token"], r["expires_in"])
                    response.add_cookie(
                        "bearer_token",
                        bearer_token,
                        max_age=r["expires_in"],
                        domain=f".{os.getenv("DOMAIN")}",
                        samesite="Strict",
                        httponly=True
                    )

                response = await f(request, *args, **kwargs)
                return response
            else:
                return redirect("/auth/login")

        return decorated_function

    return decorator(wrapped)
