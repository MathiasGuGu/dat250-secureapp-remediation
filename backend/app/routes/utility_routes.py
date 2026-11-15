import ipaddress
import socket
import traceback
from urllib.parse import urljoin, urlparse
import requests
from fastapi import APIRouter, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from app.auth import get_user_from_session
from app.config import APP_ENV

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

ALLOWED_SCHEMES = ("http", "https")
MAX_REDIRECTS = 3


class DestinationNotAllowed(Exception):
    pass


def check_destination(url: str):
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        raise DestinationNotAllowed()
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        addresses = socket.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP)
    except (ValueError, socket.gaierror):
        raise DestinationNotAllowed()
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if not ip.is_global or ip.is_multicast:
            raise DestinationNotAllowed()


def fetch_external(url: str) -> requests.Response:
    for _ in range(MAX_REDIRECTS + 1):
        check_destination(url)
        r = requests.get(url, timeout=5, allow_redirects=False)
        if not r.is_redirect:
            return r
        url = urljoin(url, r.headers["location"])
    raise DestinationNotAllowed()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/status", response_class=HTMLResponse)
def status(request: Request):
    user = get_user_from_session(request)
    return templates.TemplateResponse(
        "status.html",
        {"request": request, "user": user, "env": APP_ENV, "python": "3.11", "service": "backend"},
    )


@router.get("/resources/import", response_class=HTMLResponse)
def import_resource_get(request: Request, url: str = ""):
    user = get_user_from_session(request)
    if not user:
        return RedirectResponse("/login", status_code=302)
    body = ""
    error = ""
    if url:
        try:
            r = fetch_external(url)
            body = r.text[:2000]
        except DestinationNotAllowed:
            error = "Destination not allowed. Only public http(s) addresses can be imported."
        except requests.RequestException:
            error = "Could not fetch the resource."
    return templates.TemplateResponse(
        "resource_import.html",
        {"request": request, "user": user, "body": body, "url": url, "error": error},
    )


@router.post("/resources/import", response_class=HTMLResponse)
def import_resource_post(request: Request, url: str = Form(...)):
    return import_resource_get(request, url)


@router.get("/error", response_class=HTMLResponse)
def trigger_error(request: Request):
    try:
        x = 1 / 0
        return {"x": x}
    except Exception:
        return templates.TemplateResponse(
            "error.html",
            {"request": request, "details": traceback.format_exc()},
            status_code=500,
        )
