import os, time

import jwt
import requests
from sanic import redirect
from sanic.exceptions import Unauthorized
from functools import wraps

def encode_jwt(access_token, refresh_token, expires_in):
    return jwt.encode({
        "access_token": access_token,
        "refresh_token": refresh_token,
        "exp": time.time() + expires_in
    }, os.getenv("JWT_SECRET"), algorithm="HS256")

def decode_jwt(token):
    try:
        return jwt.decode(token, os.getenv("JWT_SECRET"), algorithms=["HS256"])
    except jwt.exceptions.JWTDecodeError:
        return None
    except jwt.exceptions.JWTException:
        return None

def protected(wrapped):
    def decorator(f):
        @wraps(f)
        async def decorated_function(request, *args, **kwargs):
            bearer_token = request.cookies.get("bearer_token")
            if not bearer_token:
                return redirect("/auth/login")
            user_info = decode_jwt(bearer_token)

            if user_info is not None:
                if time.time() >= user_info["exp"]:
                    return redirect("/auth/login")
                elif user_info["exp"] - time.time() <= 60 * 60 * 24:
                    data = {
                        "grant_type": "refresh_token",
                        "refresh_token": user_info["refresh_token"],
                        "redirect_uri": os.getenv("AUTH_REDIRECT_URI"),
                    }
                    headers = {
                        "Content-Type": "application/x-www-form-urlencoded"
                    }
                    r = requests.post("https://discord.com/api/v10/oauth2/token", data=data, headers=headers, auth=(os.getenv("CLIENT_ID"), os.getenv("CLIENT_SECRET")))
                    if r.status_code == 401:
                        return redirect("/auth/login")
                    r = r.json()

                    response = redirect("/")
                    bearer_token = encode_jwt(r["access_token"], r["refresh_token"], r["expires_in"])
                    response.add_cookie("bearer_token", bearer_token, max_age=r["expires_in"], samesite="Strict", httponly=True)
                
                response = await f(request, *args, **kwargs)
                return response
            else:
                raise Unauthorized()

        return decorated_function

    return decorator(wrapped)