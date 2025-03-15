__version__ = "1.1.2"

import html
import os
import urllib.parse

from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
from sanic import Sanic, response, redirect
from sanic.exceptions import NotFound, BadRequest, Unauthorized
from jinja2 import Environment, FileSystemLoader
import requests

from core.auth import encode_bearer_token, protected
from core.models import LogEntry

load_dotenv()

if "URL_PREFIX" in os.environ:
    print("Using the legacy config var `URL_PREFIX`, rename it to `LOG_URL_PREFIX`")
    prefix = os.environ["URL_PREFIX"]
else:
    prefix = os.getenv("LOG_URL_PREFIX", "/logs")

if prefix == "NONE":
    prefix = ""

MONGO_URI = os.getenv("MONGO_URI") or os.getenv("CONNECTION_URI")
if not MONGO_URI:
    print(
        "No CONNECTION_URI config var found. "
        "Please enter your MongoDB connection URI in the configuration or .env file."
    )
    exit(1)

app = Sanic(__name__)

app.config.CLIENT_ID = os.getenv("CLIENT_ID")
app.config.CLIENT_SECRET = os.getenv("CLIENT_SECRET")
app.config.AUTH_REDIRECT_URI = os.getenv("AUTH_REDIRECT_URI")
app.config.AUTH_OAUTH2_URI = f"https://discord.com/oauth2/authorize?client_id={app.config.CLIENT_ID}&response_type=code&redirect_uri={urllib.parse.quote(app.config.AUTH_REDIRECT_URI)}&scope=guilds.members.read"
app.config.GUILD_ID = os.getenv("GUILD_ID")

app.static("/static", "./static")

jinja_env = Environment(loader=FileSystemLoader("templates"))


def render_template(name, *args, **kwargs):
    template = jinja_env.get_template(name + ".html")
    return response.html(template.render(*args, **kwargs))


app.ctx.render_template = render_template


def strtobool(val):
    """
    Copied from distutils.strtobool.

    Convert a string representation of truth to true (1) or false (0).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ("y", "yes", "t", "true", "on", "1"):
        return 1
    elif val in ("n", "no", "f", "false", "off", "0"):
        return 0
    else:
        raise ValueError("invalid truth value %r" % (val,))


@app.listener("before_server_start")
async def init(app, loop):
    app.ctx.db = AsyncIOMotorClient(MONGO_URI).modmail_bot
    use_attachment_proxy = strtobool(os.getenv("USE_ATTACHMENT_PROXY", "no"))
    if use_attachment_proxy:
        app.ctx.attachment_proxy_url = os.getenv(
            "ATTACHMENT_PROXY_URL", "https://cdn.discordapp.xyz"
        )
        app.ctx.attachment_proxy_url = html.escape(app.ctx.attachment_proxy_url).rstrip(
            "/"
        )
    else:
        app.ctx.attachment_proxy_url = None


@app.exception(NotFound)
async def not_found(request, exc):
    return render_template("not_found")


@app.get("/")
async def index(request):
    return render_template("index")


@app.get(prefix + "/raw/<key>")
@protected
async def get_raw_logs_file(request, key):
    """Returns the plain text rendered log entry"""
    document = await app.ctx.db.logs.find_one({"key": key})

    if document is None:
        raise NotFound

    log_entry = LogEntry(app, document)

    return log_entry.render_plain_text()


@app.get(prefix + "/<key>")
@protected
async def get_logs_file(request, key):
    """Returns the html rendered log entry"""
    document = await app.ctx.db.logs.find_one({"key": key})

    if document is None:
        raise NotFound

    log_entry = LogEntry(app, document)

    return log_entry.render_html()


@app.get("/auth/login")
def login(_):
    return redirect(app.config.AUTH_OAUTH2_URI)


@app.get("/auth/redirect")
async def authenticate(request):
    code = request.args.get("code")
    if not code:
        raise BadRequest("Missing code query")

    r = requests.post(
        "https://discord.com/api/v10/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": app.config.AUTH_REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        auth=(app.config.CLIENT_ID, app.config.CLIENT_SECRET),
    )
    r.raise_for_status()
    r = r.json()
    access_token = r["access_token"]
    refresh_token = r["refresh_token"]
    expires_in = r["expires_in"]
    response = redirect("/")

    r = requests.get(
        f"https://discord.com/api/v10/users/@me/guilds/{app.config.GUILD_ID}/member",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    r.raise_for_status()
    r = r.json()
    oauth_whitelist = (await app.ctx.db.config.find_one())["oauth_whitelist"]
    whitelisted = False
    if int(r["user"]["id"]) in oauth_whitelist:
        whitelisted = True
    if not whitelisted:
        for role_id in r["roles"]:
            if int(role_id) in oauth_whitelist:
                whitelisted = True
                break
    if not whitelisted:
        raise Unauthorized()
    bearer_token = encode_bearer_token(access_token, refresh_token, expires_in)
    response.add_cookie(
        "bearer_token",
        bearer_token,
        max_age=expires_in,
        domain=f".{os.getenv("DOMAIN")}",
        samesite="Strict",
        httponly=True,
    )
    return response


if __name__ == "__main__":
    app.run(
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", 8000)),
        debug=bool(os.getenv("DEBUG", False)),
    )
