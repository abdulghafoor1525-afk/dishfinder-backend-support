"""DishFinder API: account-first authentication, sync and subscriptions."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from html import escape
from pathlib import Path
from typing import Literal, Optional
import asyncio
import os
import secrets
import uuid

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, FastAPI, HTTPException, UploadFile, File, Header
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket
import gridfs
from bson import ObjectId
from bson.errors import InvalidId
from passlib.context import CryptContext
from pydantic import BaseModel, ConfigDict, EmailStr, Field
from pymongo import ReturnDocument
from pymongo.errors import DuplicateKeyError

try:
    from .email_service import EmailConfigurationError, EmailDeliveryError, send_verification_email
except ImportError:  # Supports `cd backend && uvicorn server:app`.
    from email_service import EmailConfigurationError, EmailDeliveryError, send_verification_email

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]
fs = AsyncIOMotorGridFSBucket(db)

JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
# Keep guest sessions usable during transient refresh failures. The separate
# installation credential recovers their identity and quota after expiry.
ANONYMOUS_ACCESS_TOKEN_EXPIRE_DAYS = max(
    7, int(os.environ.get("ANONYMOUS_ACCESS_TOKEN_EXPIRE_DAYS", "7"))
)
ANONYMOUS_REFRESH_TOKEN_EXPIRE_DAYS = max(
    ANONYMOUS_ACCESS_TOKEN_EXPIRE_DAYS,
    int(os.environ.get("ANONYMOUS_REFRESH_TOKEN_EXPIRE_DAYS", str(REFRESH_TOKEN_EXPIRE_DAYS))),
)
GOOGLE_MAPS_API_KEY = os.environ.get("GOOGLE_MAPS_API_KEY", "")
EMAIL_VERIFICATION_EXPIRE_MINUTES = max(
    15, int(os.environ.get("EMAIL_VERIFICATION_EXPIRE_MINUTES", "60"))
)
EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS = max(
    30, int(os.environ.get("EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS", "60"))
)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)
users_collection = db.get_collection("users")
favourites_collection = db.get_collection("favourites")
search_history_collection = db.get_collection("search_history")
subscriptions_collection = db.get_collection("subscriptions")
sessions_collection = db.get_collection("sessions")
devices_collection = db.get_collection("devices")
device_quotas_collection = db.get_collection("device_quotas")
FREE_SEARCH_LIMIT = 3

app = FastAPI(title="DishFinder API")
app.add_middleware(
    CORSMiddleware,
    # Set CORS_ORIGINS to the production web origin(s); native apps do not use CORS.
    allow_origins=[origin for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Device-Token"],
)
api_router = APIRouter(prefix="/api")
auth_router = APIRouter(prefix="/api/auth")


class UserCreate(BaseModel):
    """Resume the guest identity belonging to this installation."""
    model_config = ConfigDict(extra="forbid")


class DeviceRegistration(BaseModel):
    platform: Literal["android", "ios", "web"]
    android_id: Optional[str] = Field(default=None, pattern=r"^[0-9a-fA-F]{16}$")
    # The legacy local counter may raise usage during migration, never lower it.
    legacy_search_count: int = Field(default=0, ge=0, le=FREE_SEARCH_LIMIT)


class AuthRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class AuthLogin(AuthRegister):
    pass


class TokenRefreshRequest(BaseModel):
    refresh_token: str


class EmailVerificationRequest(BaseModel):
    email: EmailStr


class SearchRequest(BaseModel):
    dish_name: str = Field(min_length=1, max_length=160)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    radius_miles: float = Field(gt=0, le=50)


class FavoriteCreate(BaseModel):
    place_id: str = Field(min_length=1, max_length=300)
    name: str = Field(min_length=1, max_length=300)
    address: str = Field(min_length=1, max_length=600)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    rating: Optional[float] = Field(default=None, ge=0, le=5)


class SubscriptionSync(BaseModel):
    """Subscription state supplied by the RevenueCat mobile SDK after a purchase, restore, or refresh."""

    entitlement_identifier: Literal["dishfinder_pro"]
    active: bool
    plan: Literal["free", "monthly", "annual"]
    product_identifier: Optional[str] = Field(default=None, max_length=255)
    product_plan_identifier: Optional[str] = Field(default=None, max_length=255)
    active_product_identifiers: list[str] = Field(default_factory=list, max_length=20)
    price_amount: Optional[float] = Field(default=None, ge=0)
    price_currency: Optional[str] = Field(default=None, min_length=3, max_length=12)
    price_display: Optional[str] = Field(default=None, max_length=64)
    expires_at: Optional[datetime] = None
    will_renew: Optional[bool] = None
    store: Optional[str] = Field(default=None, max_length=64)
    ownership_type: Optional[str] = Field(default=None, max_length=64)
    period_type: Optional[str] = Field(default=None, max_length=64)
    subscription_status: Optional[str] = Field(default=None, max_length=64)
    pending_plan: Optional[Literal["monthly", "annual"]] = None
    pending_product_identifier: Optional[str] = Field(default=None, max_length=255)
    pending_activation_at: Optional[datetime] = None
    preserve_pending_change: bool = False


def utcnow() -> datetime:
    # Motor returns naïve UTC datetimes by default, so use the same representation everywhere.
    return datetime.utcnow()


def as_utc_naive(value: Optional[datetime]) -> Optional[datetime]:
    """Mongo's default codec uses naïve UTC datetimes; normalize SDK ISO timestamps before comparing/storing."""
    if value and value.tzinfo:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def serialize(doc):
    if doc is None:
        return None
    if isinstance(doc, list):
        return [serialize(item) for item in doc]
    if isinstance(doc, dict):
        return {key: (str(value) if key == "_id" else serialize(value)) for key, value in doc.items()}
    if isinstance(doc, ObjectId):
        return str(doc)
    if isinstance(doc, datetime):
        # Mongo stores UTC timestamps without tzinfo. Include the UTC offset in
        # API responses so mobile clients do not reinterpret renewal dates as
        # device-local wall-clock values after an app restart.
        utc_value = doc if doc.tzinfo else doc.replace(tzinfo=timezone.utc)
        return utc_value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return doc


def safe_user(user: dict) -> dict:
    result = serialize(user)
    for private_field in (
        "_quota_id",
        "legacy_quota_migrated",
        "legacy_quota_id",
        "password_hash",
        "email_verification_token",
        "email_verification_expires",
        "email_verification_sent_at",
        "email_verification_request_id",
    ):
        result.pop(private_field, None)
    # Accounts created before email verification was introduced remain valid.
    result.setdefault("is_email_verified", True)
    return result


def token_hash(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def new_email_verification(user_id: str) -> tuple[str, str, datetime]:
    """Return a 256-bit raw token, its digest, and its UTC expiry."""
    raw_token = f"{user_id}.{secrets.token_urlsafe(32)}"
    return (
        raw_token,
        token_hash(raw_token),
        utcnow() + timedelta(minutes=EMAIL_VERIFICATION_EXPIRE_MINUTES),
    )


async def deliver_verification_email(email: str, raw_token: str) -> None:
    try:
        await asyncio.to_thread(send_verification_email, email, raw_token)
    except (EmailConfigurationError, EmailDeliveryError):
        # Details can contain provider/account data, so return a stable message only.
        raise HTTPException(
            status_code=503,
            detail={
                "code": "EMAIL_DELIVERY_FAILED",
                "message": "We could not send the verification email. Please try again shortly.",
            },
        )


def verification_result_page(
    title: str,
    message: str,
    successful: bool,
    status_code: int = 200,
) -> HTMLResponse:
    accent = "#2f855a" if successful else "#c53030"
    icon = "✓" if successful else "!"
    content = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{escape(title)}</title>
  </head>
  <body style="margin:0;background:#303743;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#fff;">
    <main style="min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;box-sizing:border-box;">
      <section style="width:100%;max-width:480px;background:#3d4451;border-radius:18px;padding:36px 28px;text-align:center;box-sizing:border-box;">
        <div style="width:58px;height:58px;line-height:58px;margin:0 auto 20px;border-radius:50%;background:{accent};font-size:30px;font-weight:700;">{icon}</div>
        <h1 style="margin:0 0 14px;color:#D6C5AB;font-size:27px;">{escape(title)}</h1>
        <p style="margin:0;color:#e5e7eb;font-size:16px;line-height:1.6;">{escape(message)}</p>
      </section>
    </main>
  </body>
</html>"""
    return HTMLResponse(content=content, status_code=status_code)


def create_access_token(user: dict, session_id: str) -> str:
    now = utcnow()
    expires_at = (
        now + timedelta(days=ANONYMOUS_ACCESS_TOKEN_EXPIRE_DAYS)
        if user.get("is_anonymous")
        else now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return jwt.encode(
        {"sub": user["id"], "sid": session_id, "typ": "access", "jti": str(uuid.uuid4()), "iat": now, "exp": expires_at},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def session_expire_days(user: dict) -> int:
    return (
        ANONYMOUS_REFRESH_TOKEN_EXPIRE_DAYS
        if user.get("is_anonymous")
        else REFRESH_TOKEN_EXPIRE_DAYS
    )


def create_refresh_token(user: dict, session_id: str) -> str:
    now = utcnow()
    return jwt.encode(
        {"sub": user["id"], "sid": session_id, "typ": "refresh", "jti": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(days=session_expire_days(user))},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


async def quota_user(user: dict, quota_id: str) -> dict:
    """Project device usage onto an account without storing it on the account."""
    # Claim a legacy account's migration destination atomically. Persist the
    # destination before applying its floor so retries after a crash are safe
    # and simultaneous logins on different devices cannot migrate it twice.
    if not user.get("legacy_quota_migrated"):
        legacy = await users_collection.find_one_and_update(
            {"id": user["id"], "legacy_quota_id": {"$exists": False}, "legacy_quota_migrated": {"$ne": True}},
            {"$set": {"legacy_quota_id": quota_id}},
            return_document=ReturnDocument.AFTER,
        ) or await users_collection.find_one({"id": user["id"]})
        if legacy and not legacy.get("legacy_quota_migrated"):
            legacy_count = min(FREE_SEARCH_LIMIT, max(0, legacy.get("search_count", 0)))
            if legacy_count:
                await device_quotas_collection.update_one(
                    {"_id": legacy["legacy_quota_id"]}, {"$max": {"search_count": legacy_count}}
                )
            await users_collection.update_one(
                {"id": user["id"]}, {"$set": {"legacy_quota_migrated": True}}
            )
    quota = await device_quotas_collection.find_one({"_id": quota_id})
    if quota is None:
        raise HTTPException(status_code=401, detail="Device registration required")
    return {**user, "_quota_id": quota_id, "search_count": quota["search_count"]}


async def require_device(x_device_token: Optional[str] = Header(default=None)) -> dict:
    if not x_device_token or not 32 <= len(x_device_token) <= 200:
        raise HTTPException(status_code=401, detail="Device registration required")
    device = await devices_collection.find_one({"_id": token_hash(x_device_token)})
    if not device:
        raise HTTPException(status_code=401, detail="Invalid device credential")
    return device


async def bind_session_device(session: dict, device: dict) -> dict:
    """A bearer session cannot be moved to a fresh device to reset its quota."""
    if session.get("device_id") and session["device_id"] != device["_id"]:
        raise HTTPException(status_code=401, detail="Session belongs to another device")
    if not session.get("device_id"):
        bound = await sessions_collection.find_one_and_update(
            {"id": session["id"], "device_id": {"$exists": False}},
            {"$set": {"device_id": device["_id"], "quota_id": device["quota_id"]}},
            return_document=ReturnDocument.AFTER,
        )
        session = bound or await sessions_collection.find_one({"id": session["id"]})
        if session.get("device_id") != device["_id"]:
            raise HTTPException(status_code=401, detail="Session belongs to another device")
    return session


@auth_router.post("/device")
async def register_device(
    data: DeviceRegistration,
    x_device_token: Optional[str] = Header(default=None),
):
    if x_device_token:
        device = await require_device(x_device_token)
        raw_token = x_device_token
    else:
        if data.platform == "android" and not data.android_id:
            raise HTTPException(status_code=422, detail="Android device identifier required")
        raw_token = secrets.token_urlsafe(32)
        device_id = token_hash(raw_token)
        quota_id = token_hash(f"android:{data.android_id.lower()}") if data.platform == "android" else device_id
        # Mongo's _id uniqueness makes concurrent enrollments share one budget.
        try:
            await device_quotas_collection.update_one(
                {"_id": quota_id},
                {"$setOnInsert": {"search_count": 0, "created_at": utcnow()}},
                upsert=True,
            )
        except DuplicateKeyError:
            pass
        device = {"_id": device_id, "quota_id": quota_id, "guest_user_id": str(uuid.uuid4()), "created_at": utcnow()}
        await devices_collection.insert_one(device)
    if data.legacy_search_count:
        await device_quotas_collection.update_one(
            {"_id": device["quota_id"]},
            {"$max": {"search_count": data.legacy_search_count}},
        )
    return {"device_token": raw_token}


async def issue_session(user: dict, device: dict, session_id: Optional[str] = None) -> dict:
    """Issue a rotated refresh token bound permanently to this device's quota."""
    session_id = session_id or str(uuid.uuid4())
    refresh_token = create_refresh_token(user, session_id)
    expires_at = utcnow() + timedelta(days=session_expire_days(user))
    await sessions_collection.update_one(
        {"id": session_id},
        {"$set": {"user_id": user["id"], "device_id": device["_id"], "quota_id": device["quota_id"], "refresh_token_hash": token_hash(refresh_token), "expires_at": expires_at, "revoked_at": None, "updated_at": utcnow()}, "$setOnInsert": {"id": session_id, "created_at": utcnow()}},
        upsert=True,
    )
    return {"access_token": create_access_token(user, session_id), "refresh_token": refresh_token, "token_type": "bearer", "user": safe_user(await quota_user(user, device["quota_id"]))}


async def decode_credentials(credentials: Optional[HTTPAuthorizationCredentials], device: Optional[dict] = None) -> tuple[dict, dict]:
    if credentials is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("typ") != "access" or not payload.get("sub") or not payload.get("sid"):
            raise JWTError("wrong token type")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired access token")
    session = await sessions_collection.find_one({"id": payload["sid"], "user_id": payload["sub"], "revoked_at": None})
    if not session:
        raise HTTPException(status_code=401, detail="Session has ended")
    user = await users_collection.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if device:
        session = await bind_session_device(session, device)
    if session.get("quota_id"):
        user = await quota_user(user, session["quota_id"])
    else:
        # Old clients must update before accessing protected data/searches.
        raise HTTPException(status_code=426, detail="Please update DishFinder to continue")
    return user, payload


async def require_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security), x_device_token: Optional[str] = Header(default=None)) -> dict:
    device = await require_device(x_device_token) if x_device_token else None
    user, _ = await decode_credentials(credentials, device)
    if not user.get("is_anonymous") and user.get("is_email_verified") is False:
        raise HTTPException(
            status_code=403,
            detail={
                "code": "EMAIL_NOT_VERIFIED",
                "message": "Please verify your email address before continuing.",
            },
        )
    return user


async def require_session_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_device_token: Optional[str] = Header(default=None),
) -> dict:
    """Allow a pending account to inspect only its own verification state."""
    device = await require_device(x_device_token) if x_device_token else None
    user, _ = await decode_credentials(credentials, device)
    return user


async def require_registered_account(user: dict = Depends(require_auth)) -> dict:
    """Anonymous sessions may search, but cannot own or sync paid subscriptions."""
    if user.get("is_anonymous"):
        raise HTTPException(status_code=403, detail="Sign in to a DishFinder account before managing subscriptions")
    return user


async def auth_context(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> tuple[dict, dict]:
    return await decode_credentials(credentials)


def assert_identity(path_user_id: str, user: dict) -> None:
    if path_user_id != user["id"]:
        raise HTTPException(status_code=403, detail="You cannot access another user's data")


def is_pro(user: dict) -> bool:
    # Paid access belongs only to registered accounts, never to the device.
    if user.get("is_anonymous"):
        return False
    expiry = user.get("pro_expires_at")
    return bool(user.get("pro")) and (expiry is None or expiry > utcnow())


def subscription_plan(data: SubscriptionSync, pro: bool) -> str:
    """Resolve a plan from the purchased product, not only a client-side label."""
    if not pro:
        return "free"
    primary_plan_id = data.product_plan_identifier.lower() if data.product_plan_identifier else ""
    if any(token in primary_plan_id for token in ("anual", "annual", "year", "p1y")):
        return "annual"
    if any(token in primary_plan_id for token in ("month", "p1m")):
        return "monthly"

    primary_product_id = data.product_identifier.lower() if data.product_identifier else ""
    # The configured Apple annual product is `dishfinder_anually_premium`.
    # `anual` intentionally accepts that spelling and the standard `annual`.
    if any(token in primary_product_id for token in ("anual", "annual", "year")):
        return "annual"
    if "month" in primary_product_id:
        return "monthly"

    # Fall back to the active-product list only for older clients that did not
    # send the entitlement's current product identifier.
    normalized_product_ids = [product_id.lower() for product_id in data.active_product_identifiers if product_id]
    if any(any(token in product_id for token in ("anual", "annual", "year")) for product_id in normalized_product_ids):
        return "annual"
    if any("month" in product_id for product_id in normalized_product_ids):
        return "monthly"
    return data.plan


def pending_subscription_change(
    data: SubscriptionSync,
    pro: bool,
    current_plan: str,
    pending_activation_at: Optional[datetime],
    existing_record: Optional[dict],
    now: Optional[datetime] = None,
) -> tuple[Optional[str], Optional[str], Optional[datetime]]:
    """Resolve an asserted or previously confirmed deferred Play plan change."""
    pending_plan = data.pending_plan if pro and data.pending_plan != current_plan else None
    pending_product_identifier = data.pending_product_identifier if pending_plan else None
    comparison_time = now or utcnow()
    if (
        pro
        and data.preserve_pending_change
        and not pending_plan
        and existing_record
    ):
        existing_pending_plan = existing_record.get("pending_plan")
        existing_pending_activation = existing_record.get("pending_activation_at")
        if (
            existing_pending_plan in ("monthly", "annual")
            and existing_pending_plan != current_plan
            and (
                existing_pending_activation is None
                or existing_pending_activation > comparison_time
            )
        ):
            return (
                existing_pending_plan,
                existing_record.get("pending_product_identifier"),
                existing_pending_activation,
            )
    if not pending_plan:
        pending_activation_at = None
    return pending_plan, pending_product_identifier, pending_activation_at


async def consume_search_quota(user: dict) -> int:
    """Atomically spend one device credit; Premium never spends free credits."""
    if is_pro(user):
        return user["search_count"]
    quota = await device_quotas_collection.find_one_and_update(
        {"_id": user["_quota_id"], "search_count": {"$lt": FREE_SEARCH_LIMIT}},
        {"$inc": {"search_count": 1}, "$set": {"updated_at": utcnow()}},
        return_document=ReturnDocument.AFTER,
    )
    if not quota:
        raise HTTPException(status_code=403, detail="SEARCH_LIMIT_REACHED")
    return quota["search_count"]


def calculate_distance_miles(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    import math
    a = math.sin(math.radians(lat2 - lat1) / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(math.radians(lon2 - lon1) / 2) ** 2
    return 3959 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


@auth_router.post("/anonymous")
@api_router.post("/users")
async def create_anonymous_user(_: UserCreate, device: dict = Depends(require_device)):
    now = utcnow()
    user_id = device["guest_user_id"]
    user = {"id": user_id, "email": f"anon-{user_id}@anonymous.invalid", "is_anonymous": True, "auth_provider": "anonymous", "legacy_quota_migrated": True, "subscription_type": "free", "pro": False, "revenuecat_app_user_id": None, "created_at": now, "updated_at": now}
    try:
        await users_collection.update_one({"id": user_id}, {"$setOnInsert": user}, upsert=True)
    except DuplicateKeyError:
        pass  # A concurrent resume already created this guest.
    return await issue_session(await users_collection.find_one({"id": user_id}), device)


@auth_router.post("/register", status_code=201)
async def auth_register(data: AuthRegister, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security), device: dict = Depends(require_device)):
    email = str(data.email).strip().lower()
    if await users_collection.find_one({"email": email, "is_anonymous": False}):
        raise HTTPException(status_code=409, detail="Email already registered")
    if credentials:
        try:
            await decode_credentials(credentials, device)  # Migrate old guest usage first.
        except HTTPException as exc:
            if exc.status_code != 401:
                raise
    user_id = str(uuid.uuid4())
    raw_token, verification_token_hash, verification_expires = new_email_verification(user_id)

    # Deliver before changing the account. An SMTP failure therefore leaves the
    # anonymous session or database exactly as it was and can be retried safely.
    await deliver_verification_email(email, raw_token)
    now = utcnow()
    verification_fields = {
        "email": email,
        "password_hash": pwd_context.hash(data.password),
        "is_anonymous": False,
        "auth_provider": "email",
        "is_email_verified": False,
        "email_verification_token": verification_token_hash,
        "email_verification_expires": verification_expires,
        "email_verification_sent_at": now,
        "updated_at": now,
    }
    # Guest favourites/history remain with the guest. New accounts own only
    # their own data; creating one does not create another search allowance.
    user = {
        "id": user_id, **verification_fields, "legacy_quota_migrated": True,
        "subscription_type": "free", "pro": False,
        "revenuecat_app_user_id": None, "created_at": now,
    }
    try:
        await users_collection.insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="Email already registered")
    session = await issue_session(user, device)
    return {
        **session,
        "success": True,
        "code": "VERIFICATION_REQUIRED",
        "message": "Account created. Please verify your email address to continue.",
        "resend_cooldown_seconds": EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS,
    }


@auth_router.post("/login")
async def auth_login(data: AuthLogin, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security), device: dict = Depends(require_device)):
    account = await users_collection.find_one({"email": str(data.email).strip().lower(), "is_anonymous": False})
    if not account or not account.get("password_hash") or not pwd_context.verify(data.password, account["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if credentials:
        try:
            await decode_credentials(credentials, device)  # Migrate usage, never copy personal data.
        except HTTPException:
            pass
    if account.get("is_email_verified") is False:
        session = await issue_session(account, device)
        return JSONResponse(
            status_code=403,
            content={
                **session,
                "success": False,
                "code": "EMAIL_NOT_VERIFIED",
                "message": "Please verify your email address before continuing.",
                "resend_cooldown_seconds": EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS,
            },
        )
    return await issue_session(account, device)


@auth_router.get("/verify-email", response_class=HTMLResponse)
async def verify_email(token: Optional[str] = None):
    if not token or not 20 <= len(token) <= 300:
        return verification_result_page(
            "Missing verification link",
            "No verification token was provided. Request a new email from the app.",
            False,
            400,
        )
    try:
        user_id, _ = token.split(".", 1)
    except ValueError:
        return verification_result_page(
            "Invalid verification link",
            "This verification link is invalid. Request a new email from the app.",
            False,
            400,
        )

    hashed_token = token_hash(token)
    account = await users_collection.find_one(
        {"id": user_id, "email_verification_token": hashed_token, "is_anonymous": False}
    )
    if not account:
        existing_account = await users_collection.find_one({"id": user_id, "is_anonymous": False})
        if existing_account and existing_account.get("is_email_verified") is not False:
            return verification_result_page(
                "Email already verified",
                "Your email is already verified. You can return to DishFinder.",
                True,
            )
        return verification_result_page(
            "Invalid verification link",
            "This verification link is invalid. Request a new email from the app.",
            False,
            400,
        )
    if account.get("email_verification_expires", utcnow()) <= utcnow():
        return verification_result_page(
            "Verification link expired",
            "This link has expired. Request a new verification email from the app.",
            False,
            410,
        )

    verified = await users_collection.update_one(
        {
            "id": user_id,
            "email_verification_token": hashed_token,
            "email_verification_expires": {"$gt": utcnow()},
            "is_email_verified": False,
        },
        {
            "$set": {"is_email_verified": True, "updated_at": utcnow()},
            "$unset": {
                "email_verification_token": "",
                "email_verification_expires": "",
                "email_verification_sent_at": "",
                "email_verification_request_id": "",
            },
        },
    )
    if not verified.modified_count:
        return verification_result_page(
            "Verification link unavailable",
            "This link could not be used. Request a new verification email from the app.",
            False,
            400,
        )
    return verification_result_page(
        "Email verified successfully",
        "You can now return to the DishFinder app and continue.",
        True,
    )


@auth_router.post("/resend-verification")
async def resend_verification(data: EmailVerificationRequest):
    email = str(data.email).strip().lower()
    account = await users_collection.find_one({"email": email, "is_anonymous": False})
    # Use the same successful response for unknown addresses to reduce account enumeration.
    if not account:
        return {
            "success": True,
            "message": "If an unverified account exists, a verification email will be sent.",
            "resend_cooldown_seconds": EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS,
        }
    if account.get("is_email_verified") is not False:
        return JSONResponse(
            status_code=409,
            content={
                "success": False,
                "code": "EMAIL_ALREADY_VERIFIED",
                "message": "This email address is already verified. You can sign in.",
            },
        )

    now = utcnow()
    last_sent = account.get("email_verification_sent_at")
    if last_sent and (now - last_sent).total_seconds() < EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS:
        retry_after = max(
            1,
            EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS - int((now - last_sent).total_seconds()),
        )
        return JSONResponse(
            status_code=429,
            content={
                "success": False,
                "code": "RESEND_COOLDOWN",
                "message": f"Please wait {retry_after} seconds before requesting another email.",
                "retry_after_seconds": retry_after,
            },
            headers={"Retry-After": str(retry_after)},
        )

    raw_token, verification_token_hash, verification_expires = new_email_verification(account["id"])
    request_id = str(uuid.uuid4())
    reserved = await users_collection.find_one_and_update(
        {
            "id": account["id"],
            "is_email_verified": False,
            "$or": [
                {"email_verification_sent_at": {"$exists": False}},
                {
                    "email_verification_sent_at": {
                        "$lte": now - timedelta(seconds=EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS)
                    }
                },
            ],
        },
        {
            "$set": {
                "email_verification_token": verification_token_hash,
                "email_verification_expires": verification_expires,
                "email_verification_sent_at": now,
                "email_verification_request_id": request_id,
                "updated_at": now,
            }
        },
        return_document=ReturnDocument.BEFORE,
    )
    if not reserved:
        return JSONResponse(
            status_code=429,
            content={
                "success": False,
                "code": "RESEND_COOLDOWN",
                "message": "Please wait before requesting another verification email.",
                "retry_after_seconds": EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS,
            },
            headers={"Retry-After": str(EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS)},
        )

    try:
        await deliver_verification_email(email, raw_token)
    except HTTPException:
        restore_set = {"updated_at": utcnow()}
        restore_unset = {"email_verification_request_id": ""}
        for field in (
            "email_verification_token",
            "email_verification_expires",
            "email_verification_sent_at",
        ):
            if field in reserved:
                restore_set[field] = reserved[field]
            else:
                restore_unset[field] = ""
        await users_collection.update_one(
            {"id": account["id"], "email_verification_request_id": request_id},
            {"$set": restore_set, "$unset": restore_unset},
        )
        raise

    await users_collection.update_one(
        {"id": account["id"], "email_verification_request_id": request_id},
        {"$unset": {"email_verification_request_id": ""}},
    )
    return {
        "success": True,
        "message": "A new verification email has been sent.",
        "resend_cooldown_seconds": EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS,
    }


@auth_router.post("/refresh")
async def auth_refresh(data: TokenRefreshRequest, device: dict = Depends(require_device)):
    try:
        payload = jwt.decode(data.refresh_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("typ") != "refresh" or not payload.get("sub") or not payload.get("sid"):
            raise JWTError("wrong token type")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    session = await sessions_collection.find_one({"id": payload["sid"], "user_id": payload["sub"]})
    if not session or session.get("revoked_at") or session.get("expires_at", utcnow()) <= utcnow() or session.get("refresh_token_hash") != token_hash(data.refresh_token):
        if session:
            await sessions_collection.update_many({"user_id": payload["sub"]}, {"$set": {"revoked_at": utcnow()}})
        raise HTTPException(status_code=401, detail="Refresh session is invalid")
    session = await bind_session_device(session, device)
    user = await users_collection.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    # Compare-and-swap makes refresh rotation single-use even if two requests race.
    next_refresh_token = create_refresh_token(user, payload["sid"])
    updated = await sessions_collection.update_one(
        {"id": payload["sid"], "refresh_token_hash": token_hash(data.refresh_token), "revoked_at": None},
        {"$set": {"refresh_token_hash": token_hash(next_refresh_token), "expires_at": utcnow() + timedelta(days=session_expire_days(user)), "updated_at": utcnow()}},
    )
    if not updated.modified_count:
        await sessions_collection.update_many({"user_id": user["id"]}, {"$set": {"revoked_at": utcnow()}})
        raise HTTPException(status_code=401, detail="Refresh session is invalid")
    return {"access_token": create_access_token(user, payload["sid"]), "refresh_token": next_refresh_token, "token_type": "bearer", "user": safe_user(await quota_user(user, device["quota_id"]))}


@auth_router.post("/logout")
async def auth_logout(context: tuple[dict, dict] = Depends(auth_context)):
    _, claims = context
    await sessions_collection.update_one({"id": claims["sid"]}, {"$set": {"revoked_at": utcnow()}})
    return {"message": "Logged out"}


@auth_router.get("/me")
async def auth_me(user: dict = Depends(require_session_user)):
    return safe_user(user)


@api_router.get("/users/me")
async def get_me(user: dict = Depends(require_auth)):
    return safe_user(user)


@api_router.get("/users/{user_id}")
async def get_user(user_id: str, user: dict = Depends(require_auth)):
    assert_identity(user_id, user)
    return safe_user(user)


@api_router.post("/users/profile-picture")
async def upload_profile_picture(file: UploadFile = File(...), user: dict = Depends(require_auth)):
    if file.content_type not in ["image/jpeg", "image/png", "image/webp"]:
        raise HTTPException(status_code=400, detail="Invalid image type. Only JPEG, PNG, and WebP are supported.")
    
    file_bytes = await file.read()
    if len(file_bytes) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image exceeds 5MB size limit.")
        
    grid_in = fs.open_upload_stream(
        file.filename, metadata={"contentType": file.content_type}
    )
    await grid_in.write(file_bytes)
    await grid_in.close()
    
    new_image_id = str(grid_in._id)
    
    # Check if there is an existing image to delete later
    old_image_id = user.get("profileImageId")
    
    # Update the user
    await users_collection.update_one(
        {"id": user["id"]},
        {"$set": {"profileImageId": new_image_id, "updated_at": utcnow()}}
    )
    
    # Delete old image if it exists
    if old_image_id:
        try:
            await fs.delete(ObjectId(old_image_id))
        except gridfs.errors.NoFile:
            pass
            
    return {"message": "Profile picture updated successfully", "profileImageId": new_image_id}


@api_router.get("/users/profile-picture/{image_id}")
async def get_profile_picture(image_id: str):
    if not ObjectId.is_valid(image_id):
        raise HTTPException(status_code=400, detail="Invalid image ID")
        
    try:
        grid_out = await fs.open_download_stream(ObjectId(image_id))
    except gridfs.errors.NoFile:
        raise HTTPException(status_code=404, detail="Profile picture not found")
        
    async def read_stream():
        while True:
            chunk = await grid_out.readchunk()
            if not chunk:
                break
            yield chunk
            
    content_type = grid_out.metadata.get("contentType", "image/jpeg") if grid_out.metadata else "image/jpeg"
    return StreamingResponse(read_stream(), media_type=content_type)


@api_router.delete("/users/profile-picture")
async def delete_profile_picture(user: dict = Depends(require_auth)):
    image_id = user.get("profileImageId")
    if not image_id:
        raise HTTPException(status_code=400, detail="No profile picture to delete")
        
    try:
        await fs.delete(ObjectId(image_id))
    except gridfs.errors.NoFile:
        pass
        
    await users_collection.update_one(
        {"id": user["id"]},
        {"$unset": {"profileImageId": ""}, "$set": {"updated_at": utcnow()}}
    )
    
    return {"message": "Profile picture deleted successfully"}



@api_router.post("/search")
async def search_restaurants(search_req: SearchRequest, user: dict = Depends(require_auth)):
    if not is_pro(user) and user["search_count"] >= FREE_SEARCH_LIMIT:
        raise HTTPException(status_code=403, detail="SEARCH_LIMIT_REACHED")
    if not GOOGLE_MAPS_API_KEY:
        raise HTTPException(status_code=503, detail="Search service is not configured")
    try:
        async with httpx.AsyncClient(timeout=30) as http_client:
            response = await http_client.get("https://maps.googleapis.com/maps/api/place/textsearch/json", params={"query": f"{search_req.dish_name} restaurant", "location": f"{search_req.latitude},{search_req.longitude}", "radius": int(max(search_req.radius_miles * 1609.34, 8046.72)), "type": "restaurant", "key": GOOGLE_MAPS_API_KEY})
            response.raise_for_status()
            payload = response.json()
    except httpx.HTTPError:
        raise HTTPException(status_code=502, detail="Restaurant search is temporarily unavailable")
    if payload.get("status") not in {"OK", "ZERO_RESULTS"}:
        raise HTTPException(status_code=502, detail="Restaurant search is temporarily unavailable")
    within, beyond = [], []
    for place in payload.get("results", [])[:20]:
        coords = place.get("geometry", {}).get("location", {})
        latitude, longitude = coords.get("lat"), coords.get("lng")
        if latitude is None or longitude is None:
            continue
        distance = round(calculate_distance_miles(search_req.latitude, search_req.longitude, latitude, longitude), 1)
        result = {"place_id": place.get("place_id", ""), "name": place.get("name", ""), "address": place.get("formatted_address", ""), "latitude": latitude, "longitude": longitude, "rating": place.get("rating"), "total_ratings": place.get("user_ratings_total"), "photo_reference": (place.get("photos") or [{}])[0].get("photo_reference"), "distance_miles": distance}
        (within if distance <= search_req.radius_miles else beyond).append(result)
    within.sort(key=lambda item: item["distance_miles"])
    beyond.sort(key=lambda item: item["distance_miles"])
    # Reserve only a completed search. This is atomic, so the fourth free result is never returned.
    search_count = await consume_search_quota(user)
    await search_history_collection.insert_one({"id": str(uuid.uuid4()), "user_id": user["id"], "dish_name": search_req.dish_name, "latitude": search_req.latitude, "longitude": search_req.longitude, "radius_miles": search_req.radius_miles, "results_count": len(within), "timestamp": utcnow()})
    return {"results": within, "results_beyond_radius": beyond, "radius_miles": search_req.radius_miles, "message": "success", "search_count": search_count, "searches_remaining": "unlimited" if is_pro(user) else max(0, FREE_SEARCH_LIMIT - search_count)}


async def history_for(user: dict):
    history = await search_history_collection.find({"user_id": user["id"]}).sort("timestamp", -1).limit(20).to_list(20)
    return {"history": serialize(history)}


@api_router.get("/search-history/me")
async def get_my_search_history(user: dict = Depends(require_auth)):
    return await history_for(user)


@api_router.get("/search-history/{user_id}")
async def get_search_history(user_id: str, user: dict = Depends(require_auth)):
    assert_identity(user_id, user)
    return await history_for(user)


@api_router.post("/favourites")
async def add_favourite(favourite: FavoriteCreate, user: dict = Depends(require_auth)):
    item = {**favourite.model_dump(), "user_id": user["id"], "created_at": utcnow()}
    result = await favourites_collection.update_one({"user_id": user["id"], "place_id": favourite.place_id}, {"$setOnInsert": item}, upsert=True)
    if not result.upserted_id:
        # A duplicate save is harmless. Returning success prevents stale local
        # favourites state from displaying a false error to the user.
        existing = await favourites_collection.find_one({"user_id": user["id"], "place_id": favourite.place_id})
        return {"message": "Already in favourites", "favourite": serialize(existing), "already_saved": True}
    return {"message": "Added to favourites", "favourite": serialize(item), "already_saved": False}


async def favourites_for(user: dict):
    favourites = await favourites_collection.find({"user_id": user["id"]}).sort("created_at", -1).to_list(100)
    return {"favourites": serialize(favourites)}


@api_router.get("/favourites/me")
async def get_my_favourites(user: dict = Depends(require_auth)):
    return await favourites_for(user)


@api_router.get("/favourites/{user_id}")
async def get_favourites(user_id: str, user: dict = Depends(require_auth)):
    assert_identity(user_id, user)
    return await favourites_for(user)


@api_router.delete("/favourites/me/{place_id}")
async def remove_my_favourite(place_id: str, user: dict = Depends(require_auth)):
    result = await favourites_collection.delete_one({"user_id": user["id"], "place_id": place_id})
    if not result.deleted_count:
        raise HTTPException(status_code=404, detail="Favourite not found")
    return {"message": "Removed from favourites"}


@api_router.delete("/favourites/{user_id}/{place_id}")
async def remove_favourite(user_id: str, place_id: str, user: dict = Depends(require_auth)):
    assert_identity(user_id, user)
    return await remove_my_favourite(place_id, user)


async def subscription_status(user: dict) -> dict:
    """Return the locally persisted state. RevenueCat is intentionally frontend-only."""
    pro = is_pro(user)
    record = await subscriptions_collection.find_one({"user_id": user["id"]}) if pro else None
    product_identifier = user.get("subscription_product_identifier") or (record or {}).get("product_identifier")
    product_plan_identifier = user.get("subscription_product_plan_identifier") or (record or {}).get("product_plan_identifier")
    plan = user.get("subscription_type", "free") if pro else "free"
    # Correct subscriptions written before annual-product detection handled the
    # configured `dishfinder_anually_premium` identifier.
    if pro and product_identifier:
        derived_plan = subscription_plan(
            SubscriptionSync(
                entitlement_identifier="dishfinder_pro",
                active=True,
                plan=plan if plan in ("monthly", "annual") else "monthly",
                product_identifier=product_identifier,
                product_plan_identifier=product_plan_identifier,
                active_product_identifiers=(record or {}).get("active_product_identifiers", []),
            ),
            pro=True,
        )
        if derived_plan != plan:
            plan = derived_plan
            await users_collection.update_one(
                {"id": user["id"]},
                {"$set": {"subscription_type": plan, "updated_at": utcnow()}},
            )
            user["subscription_type"] = plan

    price_amount = user.get("subscription_price_amount")
    price_currency = user.get("subscription_price_currency")
    price_display = user.get("subscription_price_display")
    if record:
        price_amount = price_amount if price_amount is not None else record.get("price_amount")
        price_currency = price_currency or record.get("price_currency")
        price_display = price_display or record.get("price_display")
    # will_renew only lives on the subscriptions record (not mirrored onto the
    # user doc), so it's only known once we have a record to read it from.
    will_renew = record.get("will_renew") if record else None
    pending_plan = record.get("pending_plan") if record else None
    pending_activation_at = record.get("pending_activation_at") if record else None
    return {
        "subscription_type": plan,
        "pro": pro,
        "pro_expires_at": serialize(user.get("pro_expires_at")) if pro else None,
        "will_renew": will_renew if pro else None,
        "subscription_status": record.get("subscription_status") if record and pro else None,
        "pending_plan": pending_plan if pro else None,
        "pending_product_identifier": record.get("pending_product_identifier") if record and pro else None,
        "pending_activation_at": serialize(pending_activation_at) if pro else None,
        "subscription_price_amount": price_amount if pro else None,
        "subscription_price_currency": price_currency if pro else None,
        "subscription_price_display": price_display if pro else None,
        "search_count": user.get("search_count", 0),
        "searches_remaining": "unlimited" if pro else max(0, FREE_SEARCH_LIMIT - user.get("search_count", 0)),
    }


@api_router.get("/subscriptions/status/me")
async def get_my_subscription_status(user: dict = Depends(require_auth)):
    return await subscription_status(user)


@api_router.get("/subscriptions/status/{user_id}")
async def get_subscription_status(user_id: str, user: dict = Depends(require_auth)):
    assert_identity(user_id, user)
    return await subscription_status(user)


@api_router.post("/subscriptions/sync")
async def sync_subscription(data: SubscriptionSync, user: dict = Depends(require_registered_account)):
    """Persist RevenueCat SDK state for the signed-in account without any RevenueCat server API/webhook."""
    expires_at = as_utc_naive(data.expires_at)
    pending_activation_at = as_utc_naive(data.pending_activation_at)
    pro = data.active and (expires_at is None or expires_at > utcnow())
    plan = subscription_plan(data, pro)
    existing_record = await subscriptions_collection.find_one({"user_id": user["id"]})
    pending_plan, pending_product_identifier, pending_activation_at = pending_subscription_change(
        data,
        pro,
        plan,
        pending_activation_at,
        existing_record,
    )
    synced_at = utcnow()
    record = {
        "user_id": user["id"],
        "revenuecat_app_user_id": user["id"],
        "entitlement_identifier": data.entitlement_identifier,
        "pro": pro,
        "subscription_type": plan,
        "pro_expires_at": expires_at if pro else None,
        "product_identifier": data.product_identifier,
        "product_plan_identifier": data.product_plan_identifier,
        "active_product_identifiers": data.active_product_identifiers,
        "price_amount": data.price_amount if pro else None,
        "price_currency": data.price_currency.upper() if pro and data.price_currency else None,
        "price_display": data.price_display if pro else None,
        "will_renew": data.will_renew,
        "store": data.store,
        "ownership_type": data.ownership_type,
        "period_type": data.period_type,
        "subscription_status": data.subscription_status,
        "pending_plan": pending_plan,
        "pending_product_identifier": pending_product_identifier,
        "pending_activation_at": pending_activation_at,
        "last_synced_at": synced_at,
    }
    await users_collection.update_one(
        {"id": user["id"]},
        {"$set": {
            "revenuecat_app_user_id": user["id"],
            "pro": pro,
            "subscription_type": plan,
            "pro_expires_at": record["pro_expires_at"],
            "subscription_product_identifier": data.product_identifier,
            "subscription_product_plan_identifier": data.product_plan_identifier,
            "subscription_price_amount": record["price_amount"],
            "subscription_price_currency": record["price_currency"],
            "subscription_price_display": record["price_display"],
            "updated_at": synced_at,
        }},
    )
    await subscriptions_collection.update_one(
        {"user_id": user["id"]},
        {"$set": record, "$setOnInsert": {"created_at": synced_at}},
        upsert=True,
    )
    return await subscription_status(await quota_user(await users_collection.find_one({"id": user["id"]}), user["_quota_id"]))


@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": utcnow().isoformat()}


@app.get("/terms-of-service", response_class=HTMLResponse, include_in_schema=False)
@api_router.get(
    "/terms-of-service",
    response_class=HTMLResponse,
    summary="View the DishFinder Terms of Service",
)
async def terms_of_service():
    content = """<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <meta name="theme-color" content="#303743">
    <meta name="description" content="Terms of Service for the DishFinder app.">
    <title>Terms of Service | DishFinder</title>
    <style>
      :root {
        color-scheme: dark;
        --background: #303743;
        --surface: #3d4451;
        --surface-soft: #454d5b;
        --accent: #d6c5ab;
        --text: #f8fafc;
        --muted: #d8dde5;
        --border: rgba(214, 197, 171, 0.22);
      }

      * { box-sizing: border-box; }

      html { scroll-behavior: smooth; }

      body {
        margin: 0;
        background: var(--background);
        color: var(--text);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 17px;
        line-height: 1.7;
        -webkit-font-smoothing: antialiased;
      }

      main {
        width: min(100% - 32px, 820px);
        margin: 0 auto;
        padding: 48px 0;
      }

      article {
        overflow: hidden;
        background: var(--surface);
        border: 1px solid var(--border);
        border-radius: 22px;
        box-shadow: 0 18px 48px rgba(13, 18, 27, 0.22);
      }

      header {
        padding: 42px 48px 34px;
        background: linear-gradient(145deg, var(--surface-soft), var(--surface));
        border-bottom: 1px solid var(--border);
      }

      .brand {
        margin: 0 0 10px;
        color: var(--accent);
        font-size: 0.82rem;
        font-weight: 700;
        letter-spacing: 0.12em;
        text-transform: uppercase;
      }

      h1 {
        margin: 0;
        color: var(--accent);
        font-size: clamp(2rem, 6vw, 3rem);
        line-height: 1.15;
        letter-spacing: -0.025em;
      }

      .updated {
        margin: 12px 0 0;
        color: var(--muted);
        font-size: 0.95rem;
      }

      .terms { padding: 12px 48px 44px; }

      section {
        padding: 28px 0;
        border-bottom: 1px solid var(--border);
      }

      section:last-child {
        padding-bottom: 0;
        border-bottom: 0;
      }

      h2 {
        margin: 0 0 10px;
        color: var(--accent);
        font-size: 1.25rem;
        line-height: 1.35;
      }

      p { margin: 0; }
      p + p, p + ul { margin-top: 12px; }

      ul {
        margin-bottom: 0;
        padding-left: 1.4rem;
      }

      li { padding-left: 0.25rem; }
      li + li { margin-top: 8px; }

      a {
        color: var(--accent);
        font-weight: 650;
        text-underline-offset: 3px;
      }

      a:hover { text-decoration-thickness: 2px; }

      a:focus-visible {
        outline: 3px solid var(--accent);
        outline-offset: 4px;
        border-radius: 2px;
      }

      @media (max-width: 600px) {
        body { font-size: 16px; }
        main { width: min(100% - 20px, 820px); padding: 18px 0; }
        article { border-radius: 16px; }
        header { padding: 30px 24px 26px; }
        .terms { padding: 8px 24px 32px; }
        section { padding: 24px 0; }
      }

      @media print {
        :root {
          color-scheme: light;
          --background: #ffffff;
          --surface: #ffffff;
          --surface-soft: #ffffff;
          --accent: #222222;
          --text: #222222;
          --muted: #555555;
          --border: #dddddd;
        }

        main { width: 100%; padding: 0; }
        article { border: 0; box-shadow: none; }
      }
    </style>
  </head>
  <body>
    <main>
      <article>
        <header>
          <p class="brand">DishFinder</p>
          <h1>Terms of Service</h1>
          <p class="updated">Last updated: <time datetime="2025-01">September 2026</time></p>
        </header>

        <div class="terms">
          <section>
            <h2>1. Acceptance of Terms</h2>
            <p>By accessing and using DishFinder, you accept and agree to be bound by the terms and provisions of this agreement.</p>
          </section>

          <section>
            <h2>2. Use Licence</h2>
            <p>Permission is granted to temporarily use DishFinder for personal, non-commercial use only. This is the grant of a licence, not a transfer of title.</p>
          </section>

          <section>
            <h2>3. Subscription Terms</h2>
            <p>DishFinder offers monthly and annual subscription plans:</p>
            <ul>
              <li>Monthly subscriptions are billed every month and automatically renew unless cancelled.</li>
              <li>Annual subscriptions are billed every year and automatically renew unless cancelled.</li>
              <li>Prices are provided by the App Store or Google Play in the currency supported for your account. If a price is shown in USD, your bank may charge you in its local currency.</li>
              <li>The free allowance is <strong>3 searches</strong>, shared across guest sessions and all accounts used on that device.</li>
              <li>All subscriptions can be cancelled at any time through your App Store or Google Play account settings.</li>
            </ul>
          </section>

          <section>
            <h2>4. User Accounts</h2>
            <p>You are responsible for maintaining the confidentiality of your account and for all activities that occur under your account.</p>
          </section>

          <section>
            <h2>5. Service Availability</h2>
            <p>We strive to provide uninterrupted service but cannot guarantee that DishFinder will always be available. We may suspend or terminate service at any time for maintenance or other reasons.</p>
          </section>

          <section>
            <h2>6. Location Services</h2>
            <p>DishFinder uses your device location to find nearby restaurants. You can disable location services at any time through your device settings, though this may limit app functionality.</p>
          </section>

          <section>
            <h2>7. Third-Party Services</h2>
            <p>DishFinder integrates with Google Maps and other third-party services. Your use of these services is subject to their respective terms and conditions.</p>
          </section>

          <section>
            <h2>8. Cancellation and Refunds</h2>
            <p>Monthly subscriptions can be cancelled at any time through your account settings or by contacting support. Cancellations take effect at the end of the current billing period. Refunds are handled on a case-by-case basis.</p>
          </section>

          <section>
            <h2>9. Limitation of Liability</h2>
            <p>DishFinder is provided “as is” without warranties of any kind. We are not liable for any damages arising from your use of the service.</p>
          </section>

          <section>
            <h2>10. Changes to Terms</h2>
            <p>We reserve the right to modify these terms at any time. Continued use of DishFinder after changes constitutes acceptance of the new terms.</p>
          </section>

          <section>
            <h2>11. Contact Information</h2>
            <p>For questions about these Terms of Service, please contact us at:</p>
            <p><a href="mailto:support@dishfinder.online">support@dishfinder.online</a></p>
          </section>
        </div>
      </article>
    </main>
  </body>
</html>"""
    return HTMLResponse(content=content)


@app.get("/")
async def root():
    db_status = "connected"
    try:
        await db.command("ping")
    except Exception as e:
        db_status = f"disconnected: {str(e)}"
    return {
        "status": "success",
        "message": "Backend is running successfully",
        "database": db_status
    }


app.include_router(auth_router)
app.include_router(api_router)


@app.on_event("startup")
async def initialise_database():
    if len(JWT_SECRET) < 32:
        raise RuntimeError("JWT_SECRET must be set to a random value of at least 32 characters")
    await users_collection.create_index("id", unique=True)
    await sessions_collection.create_index("id", unique=True)
    await users_collection.create_index("email", unique=True, partialFilterExpression={"is_anonymous": False})
    await users_collection.create_index(
        "email_verification_token",
        unique=True,
        partialFilterExpression={"email_verification_token": {"$type": "string"}},
    )
    await favourites_collection.create_index([("user_id", 1), ("place_id", 1)], unique=True)
    await search_history_collection.create_index([("user_id", 1), ("timestamp", -1)])
    await sessions_collection.create_index("expires_at", expireAfterSeconds=0)
    await subscriptions_collection.create_index("user_id", unique=True, partialFilterExpression={"user_id": {"$exists": True}})


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
