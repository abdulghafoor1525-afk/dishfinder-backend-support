"""DishFinder API: account-first authentication, sync and subscriptions."""
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Literal, Optional
import os
import uuid

import httpx
from dotenv import load_dotenv
from fastapi import APIRouter, Depends, FastAPI, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse
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

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ.get("MONGO_URL")
db_name = os.environ.get("DB_NAME")

client = None
db = None
fs = None

if mongo_url and db_name:
    client = AsyncIOMotorClient(mongo_url)
    db = client[db_name]
    fs = AsyncIOMotorGridFSBucket(db)


JWT_SECRET = os.environ.get("JWT_SECRET", "")
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "30"))
GOOGLE_MAPS_API_KEY = os.environ.get("GOOGLE_MAPS_API_KEY", "")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)
users_collection = db.get_collection("users") if db is not None else None
favourites_collection = db.get_collection("favourites") if db is not None else None
search_history_collection = db.get_collection("search_history") if db is not None else None
subscriptions_collection = db.get_collection("subscriptions") if db is not None else None
sessions_collection = db.get_collection("sessions") if db is not None else None

app = FastAPI(title="DishFinder API")
app.add_middleware(
    CORSMiddleware,
    # Set CORS_ORIGINS to the production web origin(s); native apps do not use CORS.
    allow_origins=[origin for origin in os.environ.get("CORS_ORIGINS", "").split(",") if origin],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)
api_router = APIRouter(prefix="/api")
auth_router = APIRouter(prefix="/api/auth")


class UserCreate(BaseModel):
    """Creates a server-issued anonymous account. Device IDs are deliberately unsupported."""
    model_config = ConfigDict(extra="forbid")


class AuthRegister(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class AuthLogin(AuthRegister):
    pass


class TokenRefreshRequest(BaseModel):
    refresh_token: str


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
    active_product_identifiers: list[str] = Field(default_factory=list, max_length=20)
    price_amount: Optional[float] = Field(default=None, ge=0)
    price_currency: Optional[str] = Field(default=None, min_length=3, max_length=12)
    price_display: Optional[str] = Field(default=None, max_length=64)
    expires_at: Optional[datetime] = None
    will_renew: Optional[bool] = None
    store: Optional[str] = Field(default=None, max_length=64)
    ownership_type: Optional[str] = Field(default=None, max_length=64)
    period_type: Optional[str] = Field(default=None, max_length=64)


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
        return doc.isoformat()
    return doc


def safe_user(user: dict) -> dict:
    result = serialize(user)
    result.pop("password_hash", None)
    return result


def token_hash(token: str) -> str:
    return sha256(token.encode("utf-8")).hexdigest()


def create_access_token(user: dict, session_id: str) -> str:
    now = utcnow()
    return jwt.encode(
        {"sub": user["id"], "sid": session_id, "typ": "access", "jti": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


def create_refresh_token(user_id: str, session_id: str) -> str:
    now = utcnow()
    return jwt.encode(
        {"sub": user_id, "sid": session_id, "typ": "refresh", "jti": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)},
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )


async def issue_session(user: dict, session_id: Optional[str] = None) -> dict:
    """Issue a rotated refresh token; only its SHA-256 digest is stored."""
    session_id = session_id or str(uuid.uuid4())
    refresh_token = create_refresh_token(user["id"], session_id)
    expires_at = utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    await sessions_collection.update_one(
        {"id": session_id},
        {"$set": {"user_id": user["id"], "refresh_token_hash": token_hash(refresh_token), "expires_at": expires_at, "revoked_at": None, "updated_at": utcnow()}, "$setOnInsert": {"id": session_id, "created_at": utcnow()}},
        upsert=True,
    )
    return {"access_token": create_access_token(user, session_id), "refresh_token": refresh_token, "token_type": "bearer", "user": safe_user(user)}


async def decode_credentials(credentials: Optional[HTTPAuthorizationCredentials]) -> tuple[dict, dict]:
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
    return user, payload


async def require_auth(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> dict:
    user, _ = await decode_credentials(credentials)
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


async def merge_anonymous_user(anonymous: dict, account: dict) -> dict:
    """Move a current anonymous session's data to the account once, preserving unique favourites."""
    if anonymous["id"] == account["id"] or not anonymous.get("is_anonymous"):
        return account
    anon_id, account_id = anonymous["id"], account["id"]
    async for favourite in favourites_collection.find({"user_id": anon_id}):
        await favourites_collection.update_one(
            {"user_id": account_id, "place_id": favourite["place_id"]},
            {"$setOnInsert": {**{key: value for key, value in favourite.items() if key != "_id"}, "user_id": account_id}},
            upsert=True,
        )
    await favourites_collection.delete_many({"user_id": anon_id})
    await search_history_collection.update_many({"user_id": anon_id}, {"$set": {"user_id": account_id}})
    # Do not grant extra free searches by converting an anonymous session into an account.
    await users_collection.update_one(
        {"id": account_id},
        {"$set": {"search_count": max(account.get("search_count", 0), anonymous.get("search_count", 0)), "updated_at": utcnow()}},
    )
    await sessions_collection.update_many({"user_id": anon_id}, {"$set": {"revoked_at": utcnow()}})
    await users_collection.delete_one({"id": anon_id, "is_anonymous": True})
    return await users_collection.find_one({"id": account_id})


def is_pro(user: dict) -> bool:
    # An anonymous session cannot unlock paid features. If a person creates an
    # account from that session, the same record becomes non-anonymous and any
    # legitimately synced subscription remains associated with the account.
    if user.get("is_anonymous"):
        return False
    expiry = user.get("pro_expires_at")
    return bool(user.get("pro")) and (expiry is None or expiry > utcnow())


def subscription_plan(data: SubscriptionSync, pro: bool) -> str:
    """Resolve a plan from the purchased product, not only a client-side label."""
    if not pro:
        return "free"
    product_ids = [data.product_identifier, *data.active_product_identifiers]
    normalized_product_ids = [product_id.lower() for product_id in product_ids if product_id]
    # The configured Apple annual product is `dishfinder_anually_premium`.
    # `anual` intentionally accepts that spelling and the standard `annual`.
    if any(any(token in product_id for token in ("anual", "annual", "year")) for product_id in normalized_product_ids):
        return "annual"
    if any("month" in product_id for product_id in normalized_product_ids):
        return "monthly"
    return data.plan


async def consume_search_quota(user_id: str) -> dict:
    """Atomically reserve a search. The fourth free search is rejected even under concurrency."""
    user = await users_collection.find_one_and_update(
        {"id": user_id, "$or": [{"pro": True, "$or": [{"pro_expires_at": None}, {"pro_expires_at": {"$gt": utcnow()}}]}, {"search_count": {"$lt": 3}}]},
        {"$inc": {"search_count": 1}, "$set": {"updated_at": utcnow()}},
        return_document=ReturnDocument.AFTER,
    )
    if not user:
        raise HTTPException(status_code=403, detail="SEARCH_LIMIT_REACHED")
    return user


def calculate_distance_miles(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    import math
    a = math.sin(math.radians(lat2 - lat1) / 2) ** 2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(math.radians(lon2 - lon1) / 2) ** 2
    return 3959 * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


@auth_router.post("/anonymous")
@api_router.post("/users")  # backwards-compatible path; never accepts or returns a device identifier
async def create_anonymous_user(_: UserCreate):
    now = utcnow()
    user = {"id": str(uuid.uuid4()), "email": f"anon-{uuid.uuid4()}@anonymous.invalid", "is_anonymous": True, "auth_provider": "anonymous", "search_count": 0, "subscription_type": "free", "pro": False, "revenuecat_app_user_id": None, "created_at": now, "updated_at": now}
    await users_collection.insert_one(user)
    return await issue_session(user)


@auth_router.post("/register")
async def auth_register(data: AuthRegister, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    email = str(data.email).lower()
    if await users_collection.find_one({"email": email, "is_anonymous": False}):
        raise HTTPException(status_code=409, detail="Email already registered")
    current = None
    if credentials:
        try:
            current, _ = await decode_credentials(credentials)
        except HTTPException:
            pass
    if current and current.get("is_anonymous"):
        await users_collection.update_one({"id": current["id"]}, {"$set": {"email": email, "password_hash": pwd_context.hash(data.password), "is_anonymous": False, "auth_provider": "email", "updated_at": utcnow()}})
        user = await users_collection.find_one({"id": current["id"]})
        await sessions_collection.update_many({"user_id": user["id"]}, {"$set": {"revoked_at": utcnow()}})
        return await issue_session(user)
    user = {"id": str(uuid.uuid4()), "email": email, "password_hash": pwd_context.hash(data.password), "is_anonymous": False, "auth_provider": "email", "search_count": 0, "subscription_type": "free", "pro": False, "revenuecat_app_user_id": None, "created_at": utcnow(), "updated_at": utcnow()}
    await users_collection.insert_one(user)
    return await issue_session(user)


@auth_router.post("/login")
async def auth_login(data: AuthLogin, credentials: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    account = await users_collection.find_one({"email": str(data.email).lower(), "is_anonymous": False})
    if not account or not account.get("password_hash") or not pwd_context.verify(data.password, account["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if credentials:
        try:
            current, _ = await decode_credentials(credentials)
            account = await merge_anonymous_user(current, account)
        except HTTPException:
            pass
    return await issue_session(account)


@auth_router.post("/refresh")
async def auth_refresh(data: TokenRefreshRequest):
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
    user = await users_collection.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    # Compare-and-swap makes refresh rotation single-use even if two requests race.
    next_refresh_token = create_refresh_token(user["id"], payload["sid"])
    updated = await sessions_collection.update_one(
        {"id": payload["sid"], "refresh_token_hash": token_hash(data.refresh_token), "revoked_at": None},
        {"$set": {"refresh_token_hash": token_hash(next_refresh_token), "expires_at": utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS), "updated_at": utcnow()}},
    )
    if not updated.modified_count:
        await sessions_collection.update_many({"user_id": user["id"]}, {"$set": {"revoked_at": utcnow()}})
        raise HTTPException(status_code=401, detail="Refresh session is invalid")
    return {"access_token": create_access_token(user, payload["sid"]), "refresh_token": next_refresh_token, "token_type": "bearer", "user": safe_user(user)}


@auth_router.post("/logout")
async def auth_logout(context: tuple[dict, dict] = Depends(auth_context)):
    _, claims = context
    await sessions_collection.update_one({"id": claims["sid"]}, {"$set": {"revoked_at": utcnow()}})
    return {"message": "Logged out"}


@auth_router.get("/me")
async def auth_me(user: dict = Depends(require_auth)):
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
    await consume_search_quota(user["id"])
    await search_history_collection.insert_one({"id": str(uuid.uuid4()), "user_id": user["id"], "dish_name": search_req.dish_name, "latitude": search_req.latitude, "longitude": search_req.longitude, "radius_miles": search_req.radius_miles, "results_count": len(within), "timestamp": utcnow()})
    return {"results": within, "results_beyond_radius": beyond, "radius_miles": search_req.radius_miles, "message": "success"}


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
    return {
        "subscription_type": plan,
        "pro": pro,
        "pro_expires_at": serialize(user.get("pro_expires_at")) if pro else None,
        "will_renew": will_renew if pro else None,
        "subscription_price_amount": price_amount if pro else None,
        "subscription_price_currency": price_currency if pro else None,
        "subscription_price_display": price_display if pro else None,
        "search_count": user.get("search_count", 0),
        "searches_remaining": "unlimited" if pro else max(0, 3 - user.get("search_count", 0)),
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
    pro = data.active and (expires_at is None or expires_at > utcnow())
    plan = subscription_plan(data, pro)
    synced_at = utcnow()
    record = {
        "user_id": user["id"],
        "revenuecat_app_user_id": user["id"],
        "entitlement_identifier": data.entitlement_identifier,
        "pro": pro,
        "subscription_type": plan,
        "pro_expires_at": expires_at if pro else None,
        "product_identifier": data.product_identifier,
        "active_product_identifiers": data.active_product_identifiers,
        "price_amount": data.price_amount if pro else None,
        "price_currency": data.price_currency.upper() if pro and data.price_currency else None,
        "price_display": data.price_display if pro else None,
        "will_renew": data.will_renew,
        "store": data.store,
        "ownership_type": data.ownership_type,
        "period_type": data.period_type,
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
    return await subscription_status(await users_collection.find_one({"id": user["id"]}))


@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": utcnow().isoformat()}


@app.get("/")
async def root():
    if client is None or db is None:
        return {
            "status": "error",
            "message": "Backend is running but database is not configured. Missing MONGO_URL or DB_NAME environment variables."
        }
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
    if not mongo_url or not db_name:
        print("WARNING: MONGO_URL or DB_NAME is missing. Database not initialized.")
        return
    if len(JWT_SECRET) < 32:
        print("WARNING: JWT_SECRET must be set to a random value of at least 32 characters")
        # Don't raise RuntimeError so we don't crash Vercel on boot, just print warning
    
    await users_collection.create_index("email", unique=True, partialFilterExpression={"is_anonymous": False})
    await favourites_collection.create_index([("user_id", 1), ("place_id", 1)], unique=True)
    await search_history_collection.create_index([("user_id", 1), ("timestamp", -1)])
    await sessions_collection.create_index("expires_at", expireAfterSeconds=0)
    await subscriptions_collection.create_index("user_id", unique=True, partialFilterExpression={"user_id": {"$exists": True}})


@app.on_event("shutdown")
async def shutdown_db_client():
    if client:
        client.close()