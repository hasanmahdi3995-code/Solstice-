import ipaddress
import json
import os
import secrets
import time
from urllib.parse import urlencode

import requests
from flask import Flask, abort, redirect, render_template_string, request, session
from upstash_redis import Redis

CLIENT_ID = os.environ["DISCORD_CLIENT_ID"]
CLIENT_SECRET = os.environ["DISCORD_CLIENT_SECRET"]
WEB_URL = os.environ["WEB_URL"].rstrip("/")
RETENTION_DAYS = int(os.getenv("RETENTION_DAYS", "90"))
REDIRECT_URI = f"{WEB_URL}/callback"

# Works with either manual UPSTASH_* vars or the ones Vercel's Upstash integration adds (KV_*).
redis = Redis(
    url=os.getenv("UPSTASH_REDIS_REST_URL") or os.environ["KV_REST_API_URL"],
    token=os.getenv("UPSTASH_REDIS_REST_TOKEN") or os.environ["KV_REST_API_TOKEN"],
)

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET"]
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax", SESSION_COOKIE_HTTPONLY=True)

PAGE = """
<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }}</title>
<style>
  body{font-family:system-ui,sans-serif;background:#1e1f22;color:#dbdee1;display:grid;place-items:center;min-height:100vh;margin:0}
  .card{background:#2b2d31;padding:2rem;border-radius:12px;max-width:440px;margin:1rem}
  h1{margin-top:0;font-size:1.4rem}
  p{line-height:1.5;font-size:.95rem}
  a.btn{display:inline-block;background:#5865f2;color:#fff;text-decoration:none;padding:.7rem 1.2rem;border-radius:8px;font-weight:600}
  small{color:#949ba4}
</style></head>
<body><div class="card">{{ body|safe }}</div></body></html>
"""


def page(title, body, status=200):
    return render_template_string(PAGE, title=title, body=body), status


def client_ip() -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    raw = (fwd.split(",")[0].strip() if fwd else "") or request.remote_addr or ""
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        abort(400)


def ip_key(raw: str) -> str:
    """IPv4 as-is; IPv6 collapsed to its /64 so one household matches."""
    ip = ipaddress.ip_address(raw)
    if ip.version == 6:
        ip = ipaddress.ip_network(f"{ip}/64", strict=False).network_address
    return str(ip)


def check_vpn(ip: str):
    """Returns (is_vpn: bool|None, kind, org, country, country_code). None = lookup failed (fail open)."""
    try:
        d = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,proxy,hosting,isp,org,country,countryCode"},
            timeout=3,
        ).json()
        if d.get("status") != "success":
            return None, "", "", "", ""
        kind = "VPN/proxy" if d.get("proxy") else ("hosting/datacenter" if d.get("hosting") else "")
        return (
            bool(d.get("proxy") or d.get("hosting")),
            kind,
            d.get("org") or d.get("isp") or "",
            d.get("country") or "",
            d.get("countryCode") or "",
        )
    except Exception:
        return None, "", "", "", ""


@app.route("/")
def index():
    return redirect("/verify")


@app.route("/verify")
def verify():
    keep = " and keeps them on record" if RETENTION_DAYS == 0 else ""
    return page(
        "Verify",
        f"""
        <h1>Sync Flips Verification For Discord</h1>
        <p>Click Below to Verify</p>
        <p><a class="btn" href="/login">Verify</a></p>
        <small>Verifying shares your Discord account and IP address with server staff{keep}.</small>
        """,
    )


@app.route("/login")
def login():
    state = secrets.token_urlsafe(24)
    session["state"] = state
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "identify",
        "state": state,
        "prompt": "none",
    }
    return redirect("https://discord.com/oauth2/authorize?" + urlencode(params))


@app.route("/callback")
def callback():
    if request.args.get("error"):
        return page("Cancelled", "<h1>Verification cancelled</h1><p>You can close this page.</p>", 400)

    code = request.args.get("code")
    state = request.args.get("state")
    if not code or not state or state != session.pop("state", None):
        abort(400)

    token = requests.post(
        "https://discord.com/api/v10/oauth2/token",
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    if token.status_code != 200:
        return page("Error", "<h1>Login failed</h1><p>Please try again.</p>", 400)

    me = requests.get(
        "https://discord.com/api/v10/users/@me",
        headers={"Authorization": f"Bearer {token.json()['access_token']}"},
        timeout=10,
    )
    if me.status_code != 200:
        return page("Error", "<h1>Login failed</h1><p>Please try again.</p>", 400)

    user = me.json()
    uid = user["id"]
    ip = client_ip()
    key = ip_key(ip)
    ttl = RETENTION_DAYS * 86400

    vpn, kind, org, country, cc = check_vpn(ip)

    redis.sadd(f"ips:{uid}", ip)
    if ttl:
        redis.expire(f"ips:{uid}", ttl)
    # A shared VPN/datacenter IP says nothing about alts, so don't use it for matching.
    if not vpn:
        redis.sadd(f"users:{key}", uid)
        if ttl:
            redis.expire(f"users:{key}", ttl)
    redis.lpush(
        "events",
        json.dumps(
            {
                "user_id": uid,
                "name": user.get("global_name") or user.get("username"),
                "ip": ip,
                "vpn": vpn,
                "kind": kind,
                "org": org,
                "country": country,
                "cc": cc,
                "ts": int(time.time()),
            }
        ),
    )
    redis.ltrim("events", 0, 999)  # cap the queue if the bot is offline

    return page(
        "Verified",
        "<h1>You're verified ✅</h1><p>Head back to Discord. Your access will be granted in a few seconds.</p>",
    )
