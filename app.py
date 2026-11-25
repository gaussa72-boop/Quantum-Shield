import os
import re
import json
import secrets
import hmac
import smtplib
import hashlib
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation, ROUND_UP
from functools import wraps

from flask import Flask, jsonify, request, session, redirect, url_for, render_template_string, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import UniqueConstraint, func, inspect, text
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from urllib.request import Request, urlopen

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "")
if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY muss in Render gesetzt sein.")
raw_db = os.getenv("DATABASE_URL", "").strip()
if raw_db.startswith("postgres://"):
    raw_db = raw_db.replace("postgres://", "postgresql+psycopg://", 1)
elif raw_db.startswith("postgresql://") and "+psycopg" not in raw_db:
    raw_db = raw_db.replace("postgresql://", "postgresql+psycopg://", 1)
if not raw_db:
    raise RuntimeError("DATABASE_URL fehlt. Für dauerhafte Mitgliederdaten ist PostgreSQL erforderlich.")
app.config.update(
    SQLALCHEMY_DATABASE_URI=raw_db,
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True, "pool_recycle": 280},
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=64 * 1024,
)
db = SQLAlchemy(app)
limiter = Limiter(get_remote_address, app=app, default_limits=["300 per hour"], storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"))
serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="ultima-membership-v1")
ALLOWED_ORIGINS = {x.strip().rstrip("/") for x in os.getenv("ALLOWED_ORIGINS", "").split(",") if x.strip()}
SETUP_TOKEN = os.getenv("ADMIN_SETUP_TOKEN", "").strip()
ADMIN_OWNER_EMAIL = os.getenv("ADMIN_OWNER_EMAIL", "").strip().lower()
PREMIUM_OWNER_EMAIL = os.getenv("PREMIUM_OWNER_EMAIL", "").strip().lower()
BTC_ADDRESS = os.getenv("BTC_RECEIVE_ADDRESS", "").strip()
BTC_NETWORK = "Bitcoin mainnet"
CRYPTO_TOPUPS_ENABLED = os.getenv("CRYPTO_TOPUPS_ENABLED", "false").lower() == "true"
AI_MODE = os.getenv("ULTIMA_AI_MODE", "multi").strip().lower()
PUBLISH_MODE = os.getenv("ULTIMA_PUBLISH_MODE", "approval").strip().lower()
if AI_MODE not in {"multi", "single", "off"}:
    AI_MODE = "multi"
if PUBLISH_MODE not in {"approval", "manual", "disabled"}:
    PUBLISH_MODE = "approval"
GENERATION_PRICES = {"ai_generation": 1, "image_generation": 2, "video_generation": 5, "music_generation": 3, "game_generation": 25, "dlc_generation": 15, "mod_generation": 10}
UNIFIED_PREMIUM_PRICE_EUR = Decimal(os.getenv("ULTIMA_PREMIUM_PRICE_EUR", "9.99"))
PREMIUM_TRIAL_DAYS = int(os.getenv("ULTIMA_PREMIUM_TRIAL_DAYS", "7"))
PREMIUM_TRIAL_USES = int(os.getenv("ULTIMA_PREMIUM_TRIAL_USES", "25"))
PREMIUM_PERIOD_DAYS = int(os.getenv("ULTIMA_PREMIUM_PERIOD_DAYS", "30"))
PREMIUM_CONFIRMATIONS_REQUIRED = int(os.getenv("ULTIMA_PREMIUM_CONFIRMATIONS", "2"))
PREMIUM_SELLER_READY = bool(os.getenv("ULTIMA_SELLER_LEGAL_NAME", "").strip() and os.getenv("ULTIMA_SELLER_ADDRESS", "").strip() and os.getenv("ULTIMA_PUBLIC_URL", "").strip())


class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    origin = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    webhook_token_hash = db.Column(db.String(64), nullable=True, unique=True, index=True)
    membership_enabled = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    members = db.relationship("Member", backref="site", lazy=True, cascade="all, delete-orphan")

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), default="superadmin", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id", ondelete="CASCADE"), nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(120), default="", nullable=False)
    bio = db.Column(db.String(1000), default="", nullable=False)
    avatar_url = db.Column(db.String(500), default="", nullable=False)
    role = db.Column(db.String(32), default="member", nullable=False)
    status = db.Column(db.String(24), default="active", nullable=False)
    token_version = db.Column(db.Integer, default=0, nullable=False)
    credit_balance = db.Column(db.Integer, default=0, nullable=False)
    is_lifetime_premium = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("site_id", "email", name="uq_member_site_email"), UniqueConstraint("site_id", "username", name="uq_member_site_username"))

class RegistrationCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id", ondelete="CASCADE"), nullable=False, index=True)
    code_hash = db.Column(db.String(64), nullable=False, unique=True, index=True)
    created_by = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    revoked_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    site = db.relationship("Site")

class CryptoPayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.relationship("Site")
    member = db.relationship("Member")
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), nullable=False, index=True)
    member_id = db.Column(db.Integer, db.ForeignKey("member.id"), nullable=False, index=True)
    amount_usd = db.Column(db.Numeric(12, 2), nullable=False)
    credits = db.Column(db.Integer, nullable=False)
    txid = db.Column(db.String(128), unique=True, nullable=False, index=True)
    network = db.Column(db.String(32), default="Bitcoin mainnet", nullable=False)
    status = db.Column(db.String(24), default="pending", nullable=False, index=True)
    reviewed_by = db.Column(db.String(255), nullable=True)
    reviewed_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class CreditLedger(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), nullable=False, index=True)
    member_id = db.Column(db.Integer, db.ForeignKey("member.id"), nullable=False, index=True)
    delta = db.Column(db.Integer, nullable=False)
    balance_after = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(80), nullable=False)
    reference = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("site_id", "member_id", "reference", name="uq_credit_ledger_reference"),)

class StoreOrder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.relationship("Site")
    site_id = db.Column(db.Integer, db.ForeignKey("site.id"), nullable=False, index=True)
    external_order_id = db.Column(db.String(128), nullable=False)
    order_number = db.Column(db.String(128), nullable=False)
    customer_name = db.Column(db.String(255), default="", nullable=False)
    customer_email = db.Column(db.String(255), default="", nullable=False)
    currency = db.Column(db.String(8), default="EUR", nullable=False)
    total_amount = db.Column(db.Numeric(12, 2), nullable=False)
    payment_status = db.Column(db.String(32), default="unknown", nullable=False)
    fulfillment_status = db.Column(db.String(32), default="new", nullable=False)
    invoice_number = db.Column(db.String(128), default="", nullable=False)
    invoice_url = db.Column(db.String(1000), default="", nullable=False)
    items_json = db.Column(db.JSON, default=list, nullable=False)
    shipping_json = db.Column(db.JSON, default=dict, nullable=False)
    source = db.Column(db.String(32), default="store", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("site_id", "external_order_id", name="uq_store_order_external"),)

class PremiumApplication(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(160), nullable=False)
    email = db.Column(db.String(255), nullable=False, index=True)
    website_url = db.Column(db.String(500), nullable=False)
    details = db.Column(db.String(2000), default="", nullable=False)
    status = db.Column(db.String(24), default="pending", nullable=False, index=True)
    stripe_session_id = db.Column(db.String(255), nullable=True, unique=True)
    stripe_subscription_id = db.Column(db.String(255), nullable=True, index=True)
    checkout_url = db.Column(db.String(1000), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    approved_at = db.Column(db.DateTime(timezone=True), nullable=True)
    paid_at = db.Column(db.DateTime(timezone=True), nullable=True)



class GlobalUser(db.Model):
    __tablename__ = "global_user"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(48), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(120), default="", nullable=False)
    bio = db.Column(db.String(1000), default="", nullable=False)
    avatar_url = db.Column(db.String(500), default="", nullable=False)
    role = db.Column(db.String(24), default="member", nullable=False)
    status = db.Column(db.String(24), default="active", nullable=False)
    token_version = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class WebsiteProject(db.Model):
    __tablename__ = "website_project"
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("global_user.id", ondelete="CASCADE"), nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    url = db.Column(db.String(500), nullable=False)
    description = db.Column(db.String(2000), default="", nullable=False)
    category = db.Column(db.String(60), default="Website", nullable=False)
    status = db.Column(db.String(24), default="draft", nullable=False, index=True)
    is_public = db.Column(db.Boolean, default=False, nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)
    owner = db.relationship("GlobalUser", backref=db.backref("website_projects", lazy=True, cascade="all, delete-orphan"))


class MentorRequest(db.Model):
    __tablename__ = "mentor_request"
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("global_user.id", ondelete="CASCADE"), nullable=False, index=True)
    mentor_id = db.Column(db.Integer, db.ForeignKey("global_user.id", ondelete="CASCADE"), nullable=False, index=True)
    topic = db.Column(db.String(180), nullable=False)
    opening_message = db.Column(db.String(3000), nullable=False)
    status = db.Column(db.String(24), nullable=False, default="pending", index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

class MentorMessage(db.Model):
    __tablename__ = "mentor_message"
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.Integer, db.ForeignKey("mentor_request.id", ondelete="CASCADE"), nullable=False, index=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("global_user.id", ondelete="CASCADE"), nullable=False, index=True)
    body = db.Column(db.String(4000), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)


class GlobalSSOCode(db.Model):
    __tablename__ = "global_sso_code"
    id = db.Column(db.Integer, primary_key=True)
    code_hash = db.Column(db.String(64), unique=True, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("global_user.id", ondelete="CASCADE"), nullable=False, index=True)
    site_id = db.Column(db.Integer, db.ForeignKey("site.id", ondelete="CASCADE"), nullable=False, index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    used_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class NetworkPremiumAccount(db.Model):
    __tablename__ = "network_premium_account"
    __table_args__ = {"extend_existing": True}
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    trial_started_at = db.Column(db.DateTime(timezone=True), nullable=True)
    trial_ends_at = db.Column(db.DateTime(timezone=True), nullable=True)
    trial_limit = db.Column(db.Integer, nullable=False, default=PREMIUM_TRIAL_USES)
    trial_used = db.Column(db.Integer, nullable=False, default=0)
    paid_until = db.Column(db.DateTime(timezone=True), nullable=True)
    renewal_disabled = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc), nullable=False)

class NetworkPremiumUsage(db.Model):
    __tablename__ = "network_premium_usage"
    __table_args__ = {"extend_existing": True}
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    site_slug = db.Column(db.String(64), nullable=False, index=True)
    feature = db.Column(db.String(64), nullable=False)
    request_id = db.Column(db.String(128), unique=True, nullable=False, index=True)
    state = db.Column(db.String(24), nullable=False, default="reserved")
    trial_charge = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

class NetworkPremiumInvoice(db.Model):
    __tablename__ = "network_premium_invoice"
    __table_args__ = {"extend_existing": True}
    id = db.Column(db.Integer, primary_key=True)
    invoice_code = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    site_slug = db.Column(db.String(64), nullable=False, default="ultima-network")
    amount_eur = db.Column(db.Numeric(10, 2), nullable=False)
    btc_eur_rate = db.Column(db.Numeric(20, 2), nullable=False)
    expected_sats = db.Column(db.BigInteger, nullable=False)
    wallet_address = db.Column(db.String(128), nullable=False)
    network = db.Column(db.String(32), nullable=False, default="Bitcoin mainnet")
    txid = db.Column(db.String(64), unique=True, nullable=True, index=True)
    paid_amount_sats = db.Column(db.BigInteger, nullable=True)
    confirmations = db.Column(db.Integer, nullable=False, default=0)
    status = db.Column(db.String(32), nullable=False, default="pending", index=True)
    expires_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    paid_at = db.Column(db.DateTime(timezone=True), nullable=True)
    paid_until = db.Column(db.DateTime(timezone=True), nullable=True)
    verification_note = db.Column(db.String(500), default="", nullable=False)


class ManagedWallet(db.Model):
    __tablename__ = "managed_wallet"
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(120), nullable=False)
    network = db.Column(db.String(40), nullable=False)
    address = db.Column(db.String(160), nullable=False)
    purpose = db.Column(db.String(240), default="Portfolio / read-only", nullable=False)
    owner_scope = db.Column(db.String(255), default="ULTIMA Owner", nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("network", "address", name="uq_managed_wallet_network_address"),)


global_serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="ultima-global-identity-v1")

def issue_global_token(user):
    return global_serializer.dumps({"user_id": user.id, "version": user.token_version})

def current_global_user():
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else ""
    if not token:
        return None
    try:
        payload = global_serializer.loads(token, max_age=30 * 24 * 60 * 60)
    except (BadSignature, SignatureExpired):
        return None
    user = db.session.get(GlobalUser, payload.get("user_id"))
    if not user or user.status != "active" or user.token_version != payload.get("version"):
        return None
    return user

def premium_checkout_ready():
    return bool(BTC_ADDRESS and PREMIUM_SELLER_READY and os.getenv("ULTIMA_PREMIUM_CRYPTO_ENABLED", "true").lower() == "true")

def premium_account_for(email, start_trial=False):
    normalized = str(email or "").strip().lower()
    account = NetworkPremiumAccount.query.filter(func.lower(NetworkPremiumAccount.email) == normalized).with_for_update().first()
    now = datetime.now(timezone.utc)
    if not account:
        account = NetworkPremiumAccount(email=normalized, trial_limit=PREMIUM_TRIAL_USES)
        db.session.add(account)
        db.session.flush()
    if start_trial and not account.trial_started_at:
        account.trial_started_at = now
        account.trial_ends_at = now + timedelta(days=PREMIUM_TRIAL_DAYS)
        account.trial_limit = PREMIUM_TRIAL_USES
        account.trial_used = 0
    return account

def premium_status_payload(email, start_trial=False):
    normalized = str(email or "").strip().lower()
    now = datetime.now(timezone.utc)
    if ADMIN_OWNER_EMAIL and normalized == ADMIN_OWNER_EMAIL:
        return {"status":"lifetime","active":True,"can_use":True,"lifetime":True,"trial_days_remaining":0,
                "trial_limit":PREMIUM_TRIAL_USES,"trial_used":0,"trial_remaining":0,
                "paid_until":None,"price_eur":str(UNIFIED_PREMIUM_PRICE_EUR),
                "period_days":PREMIUM_PERIOD_DAYS,"checkout_ready":premium_checkout_ready(),
                "wallet_configured":bool(BTC_ADDRESS),"network":BTC_NETWORK}
    account = premium_account_for(normalized, start_trial=start_trial)
    paid = bool(account.paid_until and account.paid_until > now)
    started = bool(account.trial_started_at)
    trial_time_left = bool(account.trial_ends_at and account.trial_ends_at > now)
    remaining = max(0, int(account.trial_limit or PREMIUM_TRIAL_USES) - int(account.trial_used or 0))
    trial = bool(started and trial_time_left and remaining > 0 and not paid)
    state = "paid" if paid else ("trial" if trial else ("expired" if started else "not_started"))
    db.session.commit()
    seconds = max(0, int((account.trial_ends_at - now).total_seconds())) if account.trial_ends_at and trial else 0
    return {"status":state,"active":bool(paid or trial),"can_use":bool(paid or trial),"lifetime":False,
            "trial_started":started,"trial_days_remaining":(seconds + 86399)//86400,
            "trial_limit":int(account.trial_limit or PREMIUM_TRIAL_USES),"trial_used":int(account.trial_used or 0),
            "trial_remaining":remaining,"paid_until":account.paid_until.isoformat() if account.paid_until else None,
            "renewal_disabled":bool(account.renewal_disabled),"price_eur":str(UNIFIED_PREMIUM_PRICE_EUR),
            "period_days":PREMIUM_PERIOD_DAYS,"checkout_ready":premium_checkout_ready(),
            "wallet_configured":bool(BTC_ADDRESS),"network":BTC_NETWORK,
            "message":"30-Tage-Premium-Pass, keine automatische Wallet-Abbuchung."}

def premium_reserve_usage(email, site_slug, feature, request_id):
    normalized = str(email or "").strip().lower()
    existing = NetworkPremiumUsage.query.filter_by(request_id=request_id).first()
    if existing:
        if existing.email.lower() != normalized or existing.state == "refunded":
            return False, {"status":"request_conflict","error":"Diese request_id wurde bereits verwendet."}
        return True, {"already_reserved":True,"trial":existing.trial_charge}
    if ADMIN_OWNER_EMAIL and normalized == ADMIN_OWNER_EMAIL:
        return True, {"lifetime":True,"trial":False}
    account = premium_account_for(normalized, start_trial=True)
    now = datetime.now(timezone.utc)
    paid = bool(account.paid_until and account.paid_until > now)
    remaining = max(0, int(account.trial_limit or PREMIUM_TRIAL_USES) - int(account.trial_used or 0))
    trial_time_left = bool(account.trial_ends_at and account.trial_ends_at > now)
    if not paid and (not trial_time_left or remaining <= 0):
        db.session.commit()
        return False, {"status":"expired","trial_limit":int(account.trial_limit or PREMIUM_TRIAL_USES),
                       "trial_used":int(account.trial_used or 0),"trial_remaining":remaining,
                       "price_eur":str(UNIFIED_PREMIUM_PRICE_EUR),"checkout_ready":premium_checkout_ready(),
                       "error":"Deine ULTIMA-Testphase ist beendet oder das Nutzungslimit erreicht. Premium kann zentral verlängert werden."}
    charge_trial = not paid
    if charge_trial:
        account.trial_used += 1
    db.session.add(NetworkPremiumUsage(email=normalized,site_slug=site_slug[:64],feature=feature[:64],
        request_id=request_id,state="reserved",trial_charge=charge_trial))
    db.session.commit()
    return True, {"trial":charge_trial,"trial_used":account.trial_used if charge_trial else None,
                  "trial_limit":account.trial_limit if charge_trial else None,"paid":paid}

def premium_complete_usage(email, request_id):
    event = NetworkPremiumUsage.query.filter_by(request_id=request_id, email=str(email or "").strip().lower()).with_for_update().first()
    if event and event.state == "reserved":
        event.state = "used"
        db.session.commit()
    return bool(event)

def premium_refund_usage(email, request_id):
    event = NetworkPremiumUsage.query.filter_by(request_id=request_id, email=str(email or "").strip().lower()).with_for_update().first()
    if event and event.state == "reserved":
        if event.trial_charge:
            account = NetworkPremiumAccount.query.filter(func.lower(NetworkPremiumAccount.email) == event.email.lower()).with_for_update().first()
            if account:
                account.trial_used = max(0, account.trial_used - 1)
        event.state = "refunded"
        db.session.commit()
        return True
    return False

def mempool_json(path):
    req = Request("https://mempool.space/api/" + path.lstrip("/"),
                  headers={"User-Agent":"ULTIMA-Premium-Billing/1.0","Accept":"application/json"})
    with urlopen(req, timeout=12) as response:
        return json.loads(response.read().decode("utf-8"))

def create_network_premium_invoice(email, site_slug="ultima-network"):
    if not premium_checkout_ready():
        raise ValueError("Der Kryptocheckout ist noch nicht produktiv freigeschaltet. Wallet und rechtliche Anbieterangaben müssen in Render konfiguriert sein.")
    prices = mempool_json("v1/prices")
    btc_eur = Decimal(str(prices.get("EUR", "0")))
    if not btc_eur.is_finite() or btc_eur <= 0:
        raise ValueError("Der aktuelle BTC/EUR-Kurs ist gerade nicht verfügbar.")
    sats = int((UNIFIED_PREMIUM_PRICE_EUR / btc_eur * Decimal("100000000")).to_integral_value(rounding=ROUND_UP))
    if sats <= 0:
        raise ValueError("Der errechnete Bitcoin-Rechnungsbetrag ist ungültig.")
    invoice = NetworkPremiumInvoice(invoice_code=secrets.token_urlsafe(18),email=str(email).strip().lower(),
        site_slug=site_slug[:64],amount_eur=UNIFIED_PREMIUM_PRICE_EUR,btc_eur_rate=btc_eur,
        expected_sats=sats,wallet_address=BTC_ADDRESS,network=BTC_NETWORK,status="pending",
        expires_at=datetime.now(timezone.utc)+timedelta(minutes=30))
    db.session.add(invoice)
    db.session.commit()
    btc_amount = (Decimal(sats)/Decimal("100000000")).quantize(Decimal("0.00000001"))
    return {"invoice_code":invoice.invoice_code,"email":invoice.email,"site_slug":invoice.site_slug,
            "amount_eur":str(invoice.amount_eur),"btc_eur_rate":str(invoice.btc_eur_rate),
            "expected_btc":str(btc_amount),"expected_sats":sats,"wallet":invoice.wallet_address,
            "network":invoice.network,"expires_at":invoice.expires_at.isoformat(),
            "payment_uri":"bitcoin:"+invoice.wallet_address+"?amount="+format(btc_amount,"f")}

def verify_network_premium_invoice(invoice, txid):
    txid = str(txid or "").strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}",txid):
        raise ValueError("Bitte eine gültige Bitcoin-TXID mit 64 Hex-Zeichen angeben.")
    if invoice.txid and invoice.txid != txid:
        raise ValueError("Für diese Rechnung wurde bereits eine andere Transaktion eingereicht.")
    used = NetworkPremiumInvoice.query.filter(NetworkPremiumInvoice.txid == txid, NetworkPremiumInvoice.id != invoice.id).first()
    if used:
        raise ValueError("Diese Bitcoin-TXID wurde bereits für eine andere Rechnung verwendet.")
    tx = mempool_json("tx/"+txid)
    received = sum(int(out.get("value",0)) for out in tx.get("vout",[])
                   if out.get("scriptpubkey_address") == invoice.wallet_address)
    if received < int(invoice.expected_sats):
        raise ValueError("Die Transaktion enthält noch nicht den vollständigen Rechnungsbetrag an die hinterlegte Wallet.")
    status = tx.get("status") or {}
    confirmations = 0
    if status.get("confirmed") and status.get("block_height"):
        tip = int(mempool_json("blocks/tip/height"))
        confirmations = max(0,tip-int(status["block_height"])+1)
    invoice.txid=txid
    invoice.paid_amount_sats=received
    invoice.confirmations=confirmations
    invoice.verification_note="Bitcoin mainnet · Zahlung an die konfigurierte ULTIMA-Wallet geprüft"
    if confirmations >= PREMIUM_CONFIRMATIONS_REQUIRED:
        now = datetime.now(timezone.utc)
        account = premium_account_for(invoice.email)
        base = account.paid_until if account.paid_until and account.paid_until > now else now
        account.paid_until = base + timedelta(days=PREMIUM_PERIOD_DAYS)
        account.renewal_disabled = True
        invoice.status="paid"
        invoice.paid_at=now
        invoice.paid_until=account.paid_until
        db.session.commit()
        return {"status":"paid","confirmations":confirmations,"required_confirmations":PREMIUM_CONFIRMATIONS_REQUIRED,
                "paid_until":account.paid_until.isoformat(),"message":"Zahlung bestätigt. ULTIMA Premium ist im gesamten Netzwerk freigeschaltet."}
    invoice.status="confirming" if confirmations else "awaiting_confirmations"
    db.session.commit()
    return {"status":invoice.status,"confirmations":confirmations,
            "required_confirmations":PREMIUM_CONFIRMATIONS_REQUIRED,
            "message":"Transaktion gefunden und Betrag stimmt. Premium wird nach den erforderlichen Bitcoin-Bestätigungen freigeschaltet."}

def premium_invoice_payload(invoice):
    btc_amount=(Decimal(int(invoice.expected_sats))/Decimal("100000000")).quantize(Decimal("0.00000001"))
    return {"invoice_code":invoice.invoice_code,"amount_eur":str(invoice.amount_eur),"expected_btc":str(btc_amount),
            "wallet":invoice.wallet_address,"network":invoice.network,"txid":invoice.txid,"status":invoice.status,
            "confirmations":invoice.confirmations,"expires_at":invoice.expires_at.isoformat(),
            "paid_until":invoice.paid_until.isoformat() if invoice.paid_until else None}

def clean_project_url(raw):
    value = str(raw or "").strip()
    parsed = urlparse(value)
    host = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme != "https" or not host or parsed.username or parsed.password:
        return None
    if host in {"localhost", "localhost.localdomain"} or host.endswith((".local", ".internal", ".localhost")):
        return None
    if host.replace(".", "").isdigit():
        return None
    return value[:500]

def project_payload(project):
    return {"id": project.id, "name": project.name, "slug": project.slug, "url": project.url,
            "description": project.description, "category": project.category, "status": project.status,
            "is_public": project.is_public, "created_at": project.created_at.isoformat(),
            "updated_at": project.updated_at.isoformat()}


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(255), nullable=False)
    site_slug = db.Column(db.String(64), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    target = db.Column(db.String(255), nullable=True)
    ip = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)

def audit(actor, action, site_slug=None, target=None):
    db.session.add(AuditLog(actor=actor, action=action, site_slug=site_slug, target=target, ip=(request.remote_addr or "")[:64]))
    db.session.commit()

def ai_provider_candidates():
    """Return configured OpenAI-compatible providers in a deterministic fallback order."""
    candidates = []
    configured = [
        ("ULTIMA", os.getenv("ULTIMA_AI_API_KEY", "").strip(),
         os.getenv("ULTIMA_AI_BASE_URL", "https://api.openai.com/v1").strip(),
         os.getenv("ULTIMA_AI_MODEL", "gpt-4.1-mini").strip()),
        ("OPENAI", os.getenv("OPENAI_API_KEY", "").strip(),
         "https://api.openai.com/v1", os.getenv("OPENAI_MODEL", "gpt-4.1-mini").strip()),
        ("OPENROUTER", os.getenv("OPENROUTER_API_KEY", "").strip(),
         "https://openrouter.ai/api/v1", os.getenv("OPENROUTER_MODEL", "openai/gpt-4.1-mini").strip()),
        ("GROQ", os.getenv("GROQ_API_KEY", "").strip(),
         "https://api.groq.com/openai/v1", os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile").strip()),
        ("TOGETHER", os.getenv("TOGETHER_API_KEY", "").strip(),
         "https://api.together.xyz/v1", os.getenv("TOGETHER_MODEL", "meta-llama/Llama-3.3-70B-Instruct-Turbo").strip()),
        ("DEEPSEEK", os.getenv("DEEPSEEK_API_KEY", "").strip(),
         "https://api.deepseek.com/v1", os.getenv("DEEPSEEK_MODEL", "deepseek-chat").strip()),
    ]
    preferred = os.getenv("ULTIMA_AI_PROVIDER", "").strip().upper()
    if preferred:
        configured.sort(key=lambda row: 0 if row[0] == preferred else 1)
    seen = set()
    for name, key, base_url, model in configured:
        base_url = base_url.rstrip("/")
        signature = (key, base_url)
        if not key or not base_url or not model or signature in seen:
            continue
        seen.add(signature)
        candidates.append({"provider": name.lower(), "api_key": key, "base_url": base_url, "model": model})
    return candidates

def request_ai_completion(messages):
    candidates = ai_provider_candidates()
    if not candidates:
        raise RuntimeError("Kein KI-Provider-Secret konfiguriert.")
    failures = []
    for candidate in candidates:
        provider = candidate["provider"]
        payload = {
            "model": candidate["model"],
            "messages": messages,
            "temperature": 0.4,
            "max_tokens": 1200,
        }
        headers = {"Authorization": "Bearer " + candidate["api_key"], "Content-Type": "application/json"}
        if provider == "openrouter":
            headers["HTTP-Referer"] = os.getenv("ULTIMA_PUBLIC_URL", "https://ultima-central-45ne.onrender.com")
            headers["X-Title"] = "ULTIMA Network Intelligence"
        req = Request(candidate["base_url"] + "/chat/completions",
                      data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
        try:
            with urlopen(req, timeout=25) as response:
                result = json.loads(response.read().decode("utf-8"))
            message = result.get("choices", [{}])[0].get("message", {})
            answer = message.get("content", "")
            if isinstance(answer, list):
                answer = "".join(str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in answer)
            answer = str(answer or "").strip()
            if not answer:
                raise ValueError("Leere KI-Antwort")
            return {"answer": answer, "model": candidate["model"], "provider": provider}
        except Exception as exc:
            # Never log provider secrets, request bodies or raw upstream error payloads.
            failures.append(provider + ":" + type(exc).__name__)
            app.logger.warning("AI provider %s failed (%s); trying next configured provider",
                               provider, type(exc).__name__)
    raise RuntimeError("Alle eingerichteten KI-Anbieter sind fehlgeschlagen: " + ", ".join(failures))

def site_for(slug):
    site = Site.query.filter_by(slug=slug, is_active=True).first()
    if not site or not site.membership_enabled:
        return None
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin and origin != site.origin.rstrip("/") and origin not in ALLOWED_ORIGINS:
        return None
    return site

def issue_token(member):
    return serializer.dumps({"member_id": member.id, "site_id": member.site_id, "version": member.token_version})

def current_member(slug):
    site = site_for(slug)
    if not site:
        return None, None
    header = request.headers.get("Authorization", "")
    token = header[7:] if header.lower().startswith("bearer ") else ""
    if not token:
        return site, None
    try:
        data = serializer.loads(token, max_age=43200)
    except (BadSignature, SignatureExpired):
        return site, None
    if data.get("site_id") != site.id:
        return site, None
    member = Member.query.filter_by(id=data.get("member_id"), site_id=site.id, status="active").first()
    if not member or member.token_version != data.get("version"):
        return site, None
    return site, member

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("admin_login"))
        admin = db.session.get(Admin, session["admin_id"])
        # Fail closed: the configured owner mailbox is the only central administrator.
        if not admin or not ADMIN_OWNER_EMAIL or (admin.email or "").strip().lower() != ADMIN_OWNER_EMAIL or admin.role != "superadmin":
            session.clear()
            return redirect(url_for("admin_login"))
        now = datetime.now(timezone.utc).timestamp()
        authenticated_at = float(session.get("admin_auth_at", now))
        last_seen = float(session.get("admin_last_seen", authenticated_at))
        if now - authenticated_at > 8 * 60 * 60 or now - last_seen > 30 * 60:
            session.clear()
            return redirect(url_for("admin_login"))
        session["admin_last_seen"] = now
        return fn(*args, **kwargs)
    return wrapped

def admin_csrf_ok():
    return bool(session.get("csrf") and secrets.compare_digest(session["csrf"], request.form.get("csrf", "")))

@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault("Cache-Control", "no-store" if request.path.startswith("/api/") or request.path.startswith("/admin") else "public, max-age=60")
    origin = request.headers.get("Origin", "").rstrip("/")
    if origin in ALLOWED_ORIGINS or Site.query.filter_by(origin=origin, is_active=True).first():
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, OPTIONS"
        response.headers["Vary"] = "Origin"
    return response

@app.get("/")
def home():
    return redirect(url_for("admin_login"))

@app.get("/membership-widget.js")
def membership_widget():
    return send_from_directory(os.path.dirname(__file__), "membership-widget.js", mimetype="application/javascript")

@app.get("/support-widget.js")
def support_widget():
    return send_from_directory(os.path.dirname(__file__), "support-widget.js", mimetype="application/javascript", max_age=300)

@app.get("/design-system.css")
def design_system_css():
    return send_from_directory(os.path.dirname(__file__), "design-system.css", mimetype="text/css", max_age=300)

@app.get("/health")
@limiter.exempt
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify(status="ok", service="ultima-membership-core", database="connected", global_identity="enabled", website_registry="enabled", ai_mode=AI_MODE, publish_mode=PUBLISH_MODE, publishing_requires_approval=(PUBLISH_MODE == "approval"))
    except Exception:
        app.logger.exception("Health check failed")
        return jsonify(status="degraded", database="unavailable"), 503

@app.get("/api/<slug>/config")
@limiter.limit("60 per minute")
def public_site_config(slug):
    site = site_for(slug)
    if not site:
        return jsonify(error="Webseite nicht gefunden oder nicht freigeschaltet."), 404
    return jsonify(site={"slug": site.slug, "name": site.name, "registration_enabled": True, "registration_code_required": True})

@app.post("/api/<slug>/register")
@limiter.limit("5 per hour")
def register(slug):
    site = site_for(slug)
    if not site:
        return jsonify(error="Webseite nicht gefunden."), 404
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    raw_code = str(data.get("registration_code", "")).strip()
    if not raw_code or len(raw_code) > 100:
        return jsonify(error="Ein gültiger, einmaliger Registrierungscode ist erforderlich."), 400
    code_hash = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()
    invite = RegistrationCode.query.filter_by(site_id=site.id, code_hash=code_hash).with_for_update().first()
    now = datetime.now(timezone.utc)
    if not invite or invite.used_at or invite.revoked_at or invite.expires_at <= now:
        return jsonify(error="Registrierungscode ungültig, abgelaufen oder bereits verwendet."), 403
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 255:
        return jsonify(error="Bitte gib eine gültige E-Mail-Adresse ein."), 400
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        return jsonify(error="Benutzername: 3–32 Zeichen, Buchstaben, Zahlen, Punkt, _ oder -."), 400
    if len(password) < 12 or len(password) > 128:
        return jsonify(error="Das Passwort muss 12 bis 128 Zeichen lang sein."), 400
    if Member.query.filter(func.lower(Member.email) == email, Member.site_id == site.id).first():
        return jsonify(error="Für diese Webseite existiert bereits ein Konto mit dieser E-Mail."), 409
    if Member.query.filter_by(site_id=site.id, username=username).first():
        return jsonify(error="Dieser Benutzername ist bereits vergeben."), 409
    is_owner = bool(ADMIN_OWNER_EMAIL and email == ADMIN_OWNER_EMAIL)
    member = Member(site_id=site.id, email=email, username=username, password_hash=generate_password_hash(password, method="scrypt"), display_name=str(data.get("display_name", username))[:120], role="superadmin" if is_owner else "member", status="active" if is_owner else "pending", is_lifetime_premium=bool(PREMIUM_OWNER_EMAIL and email == PREMIUM_OWNER_EMAIL))
    db.session.add(member)
    invite.used_at = now
    db.session.commit()
    audit("member:" + email, "member.register", site.slug, str(member.id))
    return jsonify(ok=True, approval_required=not is_owner, status=member.status, message="Registrierung eingegangen. Dein Konto wird nach Freigabe durch die Webseiten-Administration aktiviert." if not is_owner else "Inhaber-Konto angelegt.", token=issue_token(member) if is_owner else None, member={"id": member.id, "email": member.email, "username": member.username, "display_name": member.display_name, "role": member.role, "status": member.status, "is_lifetime_premium": member.is_lifetime_premium}), 201

@app.post("/api/<slug>/login")
@limiter.limit("10 per 15 minutes")
def login(slug):
    site = site_for(slug)
    if not site:
        return jsonify(error="Webseite nicht gefunden."), 404
    data = request.get_json(silent=True) or {}
    identity = str(data.get("identity", "")).strip()
    password = str(data.get("password", ""))
    member = Member.query.filter(Member.site_id == site.id, func.lower(Member.email) == identity.lower()).first()
    if not member:
        member = Member.query.filter_by(site_id=site.id, username=identity).first()
    if not member or member.status != "active" or not check_password_hash(member.password_hash, password):
        return jsonify(error="Anmeldedaten ungültig oder Konto nicht aktiv."), 401
    return jsonify(ok=True, token=issue_token(member), member={"id": member.id, "email": member.email, "username": member.username, "display_name": member.display_name, "role": member.role, "is_lifetime_premium": member.is_lifetime_premium})

@app.get("/api/<slug>/me")
def me(slug):
    site, member = current_member(slug)
    if not site:
        return jsonify(error="Webseite nicht gefunden."), 404
    if not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    return jsonify(member={"id": member.id, "email": member.email, "username": member.username, "display_name": member.display_name, "bio": member.bio, "avatar_url": member.avatar_url, "role": member.role, "created_at": member.created_at.isoformat(), "is_lifetime_premium": member.is_lifetime_premium})


@app.get("/api/<slug>/premium/status")
def site_premium_status(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    status = premium_status_payload(member.email)
    invoices = NetworkPremiumInvoice.query.filter(func.lower(NetworkPremiumInvoice.email) == member.email.lower()).order_by(NetworkPremiumInvoice.created_at.desc()).limit(5).all()
    status["invoices"] = [premium_invoice_payload(x) for x in invoices]
    return jsonify(premium=status)

@app.post("/api/<slug>/premium/trial/start")
@limiter.limit("3 per hour")
def site_premium_start_trial(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    status = premium_status_payload(member.email, start_trial=True)
    return jsonify(ok=True, premium=status)

@app.post("/api/<slug>/premium/authorize")
@limiter.limit("120 per hour")
def site_premium_authorize(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    if member.status != "active":
        return jsonify(error="Dein Konto ist noch nicht freigegeben."), 403
    data = request.get_json(silent=True) or {}
    feature = str(data.get("feature", "ai_generation"))[:64]
    request_id = str(data.get("request_id", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", request_id):
        return jsonify(error="Ungültige request_id."), 400
    allowed, detail = premium_reserve_usage(member.email, site.slug, feature, request_id)
    if not allowed:
        return jsonify(ok=False, premium=detail, error=detail.get("error","Premium-Nutzungslimit erreicht.")), 402
    return jsonify(ok=True, premium=detail)

@app.post("/api/<slug>/premium/complete")
def site_premium_complete(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    data = request.get_json(silent=True) or {}
    request_id = str(data.get("request_id", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", request_id):
        return jsonify(error="Ungültige request_id."), 400
    return jsonify(ok=premium_complete_usage(member.email, request_id))

@app.post("/api/<slug>/premium/refund")
def site_premium_refund(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    data = request.get_json(silent=True) or {}
    request_id = str(data.get("request_id", "")).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", request_id):
        return jsonify(error="Ungültige request_id."), 400
    return jsonify(ok=premium_refund_usage(member.email, request_id))

@app.get("/api/<slug>/premium/invoices")
def site_premium_invoices(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    rows = NetworkPremiumInvoice.query.filter(func.lower(NetworkPremiumInvoice.email) == member.email.lower()).order_by(NetworkPremiumInvoice.created_at.desc()).limit(20).all()
    return jsonify(invoices=[premium_invoice_payload(x) for x in rows])

@app.post("/api/<slug>/premium/invoices")
@limiter.limit("3 per hour")
def site_premium_invoice_create(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    try:
        invoice = create_network_premium_invoice(member.email, site.slug)
    except Exception as exc:
        app.logger.warning("Premium invoice creation unavailable: %s", type(exc).__name__)
        return jsonify(error=str(exc)[:300]), 503
    return jsonify(ok=True, invoice=invoice), 201

@app.post("/api/<slug>/premium/invoices/<invoice_code>/submit")
@limiter.limit("10 per hour")
def site_premium_invoice_submit(slug, invoice_code):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    invoice = NetworkPremiumInvoice.query.filter_by(invoice_code=invoice_code, email=member.email.lower()).first()
    if not invoice:
        return jsonify(error="Premium-Rechnung nicht gefunden."), 404
    if invoice.status == "paid":
        return jsonify(ok=True, result={"status":"paid","paid_until":invoice.paid_until.isoformat() if invoice.paid_until else None})
    if invoice.expires_at <= datetime.now(timezone.utc) and not invoice.txid:
        invoice.status = "expired"; db.session.commit()
        return jsonify(error="Diese Rechnung ist abgelaufen. Bitte eine neue Rechnung erstellen."), 410
    data = request.get_json(silent=True) or {}
    try:
        result = verify_network_premium_invoice(invoice, data.get("txid"))
    except Exception as exc:
        app.logger.info("Premium TXID verification rejected: %s", type(exc).__name__)
        return jsonify(error=str(exc)[:300]), 400
    return jsonify(ok=True, result=result, premium=premium_status_payload(member.email))

@app.post("/api/<slug>/premium/cancel")
def site_premium_cancel(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    account = premium_account_for(member.email)
    account.renewal_disabled = True
    db.session.commit()
    return jsonify(ok=True, paid_until=account.paid_until.isoformat() if account.paid_until else None,
                   message="Es gibt keine automatische Wallet-Abbuchung. Dein vorausbezahlter Zugang bleibt bis zum Ablauf aktiv.")

@app.post("/api/<slug>/copilot")
@limiter.limit("20 per hour")
def member_copilot(slug):
    site, member = current_member(slug)
    if not site:
        return jsonify(error="Webseite nicht gefunden."), 404
    if not member:
        return jsonify(error="Bitte zuerst anmelden."), 401
    if member.status != "active":
        return jsonify(error="Dein Konto ist noch nicht freigegeben."), 403
    if AI_MODE == "off":
        return jsonify(error="Der KI-Copilot ist für diese Plattform derzeit deaktiviert."), 503
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", "")).strip()
    history = data.get("history", [])
    if not message or len(message) > 4000:
        return jsonify(error="Bitte gib eine Nachricht mit maximal 4.000 Zeichen ein."), 400
    safe_history = []
    if isinstance(history, list):
        for item in history[-8:]:
            if isinstance(item, dict) and item.get("role") in ("user", "assistant"):
                content = str(item.get("content", ""))[:1500]
                if content:
                    safe_history.append({"role": item["role"], "content": content})
    if not ai_provider_candidates():
        return jsonify(error="Der Copilot ist vorbereitet. Bitte mindestens ein Provider-Secret (ULTIMA_AI_API_KEY, OPENAI_API_KEY, OPENROUTER_API_KEY, GROQ_API_KEY, TOGETHER_API_KEY oder DEEPSEEK_API_KEY) in Render einrichten."), 503

    usage_id = "copilot-" + secrets.token_urlsafe(18)
    allowed, entitlement = premium_reserve_usage(member.email, site.slug, "ai_generation", usage_id)
    if not allowed:
        return jsonify(error=entitlement.get("error"), premium=entitlement, upgrade_url="/portal"), 402
    system_prompt = (
        "Du bist ULTIMA Copilot, der individuelle KI-Assistent innerhalb einer bestimmten Website. "
        "Antworte in der Sprache des Mitglieds, standardmäßig Deutsch. "
        "Website: " + site.name + " (" + site.slug + "). "
        "Mitgliedsrolle: " + member.role + ". "
        "Behalte die eigenständige Identität, Persona, Fachdomäne, Produktlogik und Wissensbasis dieser Website bei. "
        "Vereinheitliche nicht den Charakter mit anderen ULTIMA-KIs. "
        "Hilf bei Navigation, Profil, Mitgliedschaft, Shop, Inhalten, Ideen, Website-Bedienung, "
        "Fehlersuche und Planung. Behaupte niemals, du hättest etwas veröffentlicht, gekauft, geändert "
        "oder deployed, wenn keine entsprechende bestätigte Aktion ausgeführt wurde. "
        "Du hast keinen direkten Zugriff auf private GitHub-/Render-Konten oder andere Mitgliederkonten. "
        "Fordere niemals Passwörter, API-Schlüssel, Setup-Tokens oder Zahlungsgeheimnisse an. "
        "Bei Änderungen an Preisen, Zahlungen, Konten, Veröffentlichungen oder produktivem Code "
        "erkläre den Vorschlag und verlange ausdrückliche Freigabe durch einen berechtigten Administrator."
    )
    try:
        result = request_ai_completion([{"role": "system", "content": system_prompt}] + safe_history + [{"role": "user", "content": message}])
        premium_complete_usage(member.email, usage_id)
        return jsonify(ok=True, answer=result["answer"][:8000], model=result["model"],
                        provider=result["provider"], site=site.slug, premium=entitlement,
                        request_id=usage_id)
    except Exception as exc:
        premium_refund_usage(member.email, usage_id)
        app.logger.warning("Copilot provider chain failed: %s", type(exc).__name__)
        return jsonify(error="Der KI-Dienst ist momentan nicht erreichbar. Deine Premium-Testnutzung wurde zurückerstattet."), 502

@app.patch("/api/<slug>/profile")
def update_profile(slug):
    site, member = current_member(slug)
    if not site:
        return jsonify(error="Webseite nicht gefunden."), 404
    if not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    data = request.get_json(silent=True) or {}
    member.display_name = str(data.get("display_name", member.display_name))[:120]
    member.bio = str(data.get("bio", member.bio))[:1000]
    avatar = str(data.get("avatar_url", member.avatar_url))
    if avatar and not avatar.startswith(("https://", "/")):
        return jsonify(error="Profilbild muss eine HTTPS- oder lokale URL sein."), 400
    member.avatar_url = avatar[:500]
    db.session.commit()
    return jsonify(ok=True)

@app.post("/api/<slug>/logout")
def logout(slug):
    site, member = current_member(slug)
    if not site:
        return jsonify(error="Webseite nicht gefunden."), 404
    if member:
        member.token_version += 1
        db.session.commit()
    return jsonify(ok=True)

@app.get("/api/<slug>/credits/balance")
def credit_balance(slug):
    site, member = current_member(slug)
    if not site:
        return jsonify(error="Webseite nicht gefunden."), 404
    if not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    return jsonify(balance=member.credit_balance, currency="USD", credit_value="1 credit = 1 USD", prices=GENERATION_PRICES, wallet=BTC_ADDRESS, network=BTC_NETWORK, payment_enabled=bool(BTC_ADDRESS) and CRYPTO_TOPUPS_ENABLED, premium=premium_status_payload(member.email))

@app.get("/api/<slug>/credits/history")
def credit_history(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    ledger = CreditLedger.query.filter_by(site_id=site.id, member_id=member.id).order_by(CreditLedger.created_at.desc()).limit(100).all()
    payments = CryptoPayment.query.filter_by(site_id=site.id, member_id=member.id).order_by(CryptoPayment.created_at.desc()).limit(50).all()
    return jsonify(ledger=[{"delta": x.delta, "balance": x.balance_after, "reason": x.reason, "created_at": x.created_at.isoformat()} for x in ledger], payments=[{"id": p.id, "amount_usd": str(p.amount_usd), "credits": p.credits, "txid": p.txid, "status": p.status, "created_at": p.created_at.isoformat()} for p in payments])

@app.post("/api/<slug>/credits/purchase")
@limiter.limit("5 per hour")
def credit_purchase(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    data = request.get_json(silent=True) or {}
    try:
        amount = Decimal(str(data.get("amount_usd", ""))).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return jsonify(error="Ungültiger USD-Betrag."), 400
    txid = str(data.get("txid", "")).strip().lower()
    if not amount.is_finite() or amount < Decimal("5.00") or amount > Decimal("10000.00") or amount != amount.to_integral_value():
        return jsonify(error="Bitte einen ganzen USD-Betrag zwischen 5 und 10.000 eingeben."), 400
    if not BTC_ADDRESS or not CRYPTO_TOPUPS_ENABLED:
        return jsonify(error="Krypto-Aufladungen sind bis zur Einrichtung einer dauerhaften Produktivdatenbank deaktiviert."), 503
    if not re.fullmatch(r"[a-f0-9]{64}", txid):
        return jsonify(error="Bitte eine gültige Bitcoin-Transaktions-ID mit 64 Hex-Zeichen eingeben."), 400
    if CryptoPayment.query.filter_by(txid=txid).first():
        return jsonify(error="Diese Transaktions-ID wurde bereits eingereicht."), 409
    payment = CryptoPayment(site_id=site.id, member_id=member.id, amount_usd=amount, credits=int(amount), txid=txid)
    db.session.add(payment)
    db.session.commit()
    audit("member:" + member.username, "crypto.payment_submitted", site.slug, str(payment.id))
    return jsonify(ok=True, payment_id=payment.id, status="pending", message="Zahlung eingereicht. Credits werden erst nach manueller Prüfung und Bestätigung freigeschaltet."), 201

@app.post("/api/<slug>/credits/consume")
def consume_credits(slug):
    site, member = current_member(slug)
    if not site or not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    data = request.get_json(silent=True) or {}
    feature = str(data.get("feature", ""))
    request_id = str(data.get("request_id", "")).strip()
    cost = GENERATION_PRICES.get(feature)
    if not cost or not re.fullmatch(r"[A-Za-z0-9_.:-]{8,128}", request_id):
        return jsonify(error="Unbekannte Funktion oder ungültige request_id."), 400
    reference = "generation:" + request_id
    member = Member.query.filter_by(id=member.id, site_id=site.id).with_for_update().first()
    existing = CreditLedger.query.filter_by(site_id=site.id, member_id=member.id, reference=reference).first()
    if existing:
        return jsonify(ok=True, already_charged=True, charged=abs(min(existing.delta, 0)), balance=member.credit_balance)
    # The unified network subscription supersedes isolated per-site credit balances.
    # The client normally reserves usage before generation; legacy integrations are
    # still gated here so an expired trial cannot use a hidden credit-balance bypass.
    if member.is_lifetime_premium or (ADMIN_OWNER_EMAIL and member.email.lower() == ADMIN_OWNER_EMAIL):
        return jsonify(ok=True, charged=0, balance=member.credit_balance, premium=True)
    prior_usage = NetworkPremiumUsage.query.filter_by(request_id=request_id, email=member.email.lower()).first()
    if prior_usage and prior_usage.state in {"reserved","used"}:
        if prior_usage.state == "reserved":
            prior_usage.state = "used"
            db.session.commit()
        return jsonify(ok=True, charged=0, balance=member.credit_balance, premium=True, trial=prior_usage.trial_charge)
    allowed, entitlement = premium_reserve_usage(member.email, site.slug, feature, request_id)
    if not allowed:
        return jsonify(error=entitlement.get("error"), premium=entitlement, required=cost, balance=member.credit_balance, upgrade_url="/portal"), 402
    premium_complete_usage(member.email, request_id)
    return jsonify(ok=True, charged=0, balance=member.credit_balance, premium=True, trial=bool(entitlement.get("trial")))

@app.post("/admin/payment/<int:payment_id>/<action>")
@admin_required
def admin_payment_review(payment_id, action):
    if not admin_csrf_ok():
        abort(400)
    payment = db.session.get(CryptoPayment, payment_id)
    if not payment or payment.status != "pending":
        abort(404)
    if action == "approve":
        member = Member.query.filter_by(id=payment.member_id, site_id=payment.site_id).with_for_update().first()
        if not member:
            abort(404)
        reference = "payment:" + str(payment.id)
        if not CreditLedger.query.filter_by(site_id=payment.site_id, member_id=member.id, reference=reference).first():
            member.credit_balance += payment.credits
            db.session.add(CreditLedger(site_id=payment.site_id, member_id=member.id, delta=payment.credits, balance_after=member.credit_balance, reason="bitcoin_topup", reference=reference))
        payment.status = "confirmed"
    elif action == "reject":
        payment.status = "rejected"
    else:
        abort(400)
    payment.reviewed_by = session.get("admin_email", "central-admin")
    payment.reviewed_at = datetime.now(timezone.utc)
    db.session.commit()
    audit("admin", "payment." + action, payment.site.slug, str(payment.id))
    return redirect(url_for("admin_home"))

@app.post("/api/integrations/<slug>/orders")
@limiter.limit("120 per hour")
def ingest_store_order(slug):
    site = Site.query.filter_by(slug=slug, is_active=True).first()
    supplied = request.headers.get("X-ULTIMA-ORDER-TOKEN", "")
    if not site or not site.webhook_token_hash or not supplied or not secrets.compare_digest(site.webhook_token_hash, hashlib.sha256(supplied.encode("utf-8")).hexdigest()):
        return jsonify(error="Integration nicht autorisiert."), 401
    data = request.get_json(silent=True) or {}
    external_id = str(data.get("external_order_id", "")).strip()[:128]
    order_number = str(data.get("order_number", external_id)).strip()[:128]
    if not external_id or not order_number:
        return jsonify(error="Bestell-ID und Bestellnummer sind erforderlich."), 400
    try:
        total = Decimal(str(data.get("total_amount", "0"))).quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return jsonify(error="Ungültiger Bestellbetrag."), 400
    if not total.is_finite() or total < 0 or total > Decimal("10000000"):
        return jsonify(error="Ungültiger Bestellbetrag."), 400
    items = data.get("items", [])
    if not isinstance(items, list) or len(items) > 200:
        return jsonify(error="Ungültige Bestellpositionen."), 400
    safe_items = []
    for item in items:
        if isinstance(item, dict):
            safe_items.append({k: str(item.get(k, ""))[:300] for k in ("name", "sku", "variant", "quantity", "unit_price", "total")})
    order = StoreOrder.query.filter_by(site_id=site.id, external_order_id=external_id).first()
    if not order:
        order = StoreOrder(site_id=site.id, external_order_id=external_id, order_number=order_number, total_amount=total)
        db.session.add(order)
    order.order_number = order_number
    order.customer_name = str(data.get("customer_name", ""))[:255]
    order.customer_email = str(data.get("customer_email", ""))[:255]
    order.currency = str(data.get("currency", "EUR"))[:8].upper()
    order.total_amount = total
    order.payment_status = str(data.get("payment_status", "unknown"))[:32]
    order.fulfillment_status = str(data.get("fulfillment_status", "new"))[:32]
    order.invoice_number = str(data.get("invoice_number", ""))[:128]
    invoice_url = str(data.get("invoice_url", ""))
    order.invoice_url = invoice_url[:1000] if invoice_url.startswith("https://") else ""
    order.items_json = safe_items
    order.shipping_json = data.get("shipping", {}) if isinstance(data.get("shipping"), dict) else {}
    order.source = str(data.get("source", "store"))[:32]
    db.session.commit()
    audit("store-webhook", "order.synced", site.slug, order.order_number)
    return jsonify(ok=True, order_id=order.id, order_number=order.order_number), 201

@app.post("/admin/site/<slug>/settings")
@admin_required
def admin_site_settings(slug):
    if not admin_csrf_ok():
        abort(400)
    site = Site.query.filter_by(slug=slug).first_or_404()
    name = request.form.get("name", "").strip()[:120]
    origin = request.form.get("origin", "").strip().rstrip("/")
    if not name or not origin.startswith("https://"):
        abort(400)
    site.name, site.origin = name, origin
    site.is_active = request.form.get("is_active") == "on"
    site.membership_enabled = request.form.get("membership_enabled") == "on"
    db.session.commit()
    audit(session.get("admin_email", "admin"), "site.settings_updated", slug, origin)
    return redirect(url_for("admin_site", slug=slug))

@app.post("/admin/site/<slug>/integration-token")
@admin_required
def rotate_site_token(slug):
    if not admin_csrf_ok():
        abort(400)
    site = Site.query.filter_by(slug=slug).first_or_404()
    token = "ult_" + secrets.token_urlsafe(48)
    site.webhook_token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    db.session.commit()
    audit(session.get("admin_email", "admin"), "site.integration_token_rotated", slug)
    return render_template_string(TOKEN_ONCE_HTML, site=site, token=token)

@app.post("/admin/site/<slug>/integration-token/revoke")
@admin_required
def revoke_site_token(slug):
    if not admin_csrf_ok():
        abort(400)
    site = Site.query.filter_by(slug=slug).first_or_404()
    site.webhook_token_hash = None
    db.session.commit()
    audit(session.get("admin_email", "admin"), "site.integration_token_revoked", slug)
    return redirect(url_for("admin_site", slug=slug))

@app.post("/admin/order/<int:order_id>/update")
@admin_required
def update_store_order(order_id):
    if not admin_csrf_ok():
        abort(400)
    order = db.session.get(StoreOrder, order_id)
    if not order:
        abort(404)
    payment = request.form.get("payment_status", order.payment_status)[:32]
    fulfillment = request.form.get("fulfillment_status", order.fulfillment_status)[:32]
    if payment not in {"unknown", "pending", "paid", "failed", "refunded", "partially_refunded"}:
        abort(400)
    if fulfillment not in {"new", "processing", "fulfilled", "shipped", "delivered", "cancelled", "returned"}:
        abort(400)
    order.payment_status, order.fulfillment_status = payment, fulfillment
    db.session.commit()
    audit(session.get("admin_email", "admin"), "order.updated", order.site.slug, order.order_number)
    return redirect(url_for("admin_site", slug=order.site.slug))

@app.post("/admin/invites/create")
@admin_required
def create_registration_code():
    if not admin_csrf_ok():
        abort(400)
    slug = request.form.get("site_slug", "").strip()
    site = Site.query.filter_by(slug=slug, is_active=True, membership_enabled=True).first_or_404()
    code = "ULT-" + secrets.token_urlsafe(18).replace("-", "").replace("_", "").upper()
    record = RegistrationCode(site_id=site.id, code_hash=hashlib.sha256(code.encode("utf-8")).hexdigest(), created_by=session.get("admin_email", "admin"), expires_at=datetime.now(timezone.utc) + timedelta(days=7))
    db.session.add(record)
    db.session.commit()
    audit("admin:" + session.get("admin_email", "admin"), "registration_code.created", slug, str(record.id))
    return "<h1>Einmaliger Registrierungscode</h1><p>Webseite: " + site.name + "</p><p>Gültig sieben Tage. Diesen Code jetzt kopieren; er wird nicht erneut angezeigt.</p><pre>" + code + "</pre><a href=/admin>Zurück zum Control Center</a>"

@app.post("/admin/invites/<int:invite_id>/revoke")
@admin_required
def revoke_registration_code(invite_id):
    if not admin_csrf_ok():
        abort(400)
    invite = db.session.get(RegistrationCode, invite_id)
    if not invite:
        abort(404)
    if not invite.used_at and not invite.revoked_at:
        invite.revoked_at = datetime.now(timezone.utc)
        db.session.commit()
        audit("admin:" + session.get("admin_email", "admin"), "registration_code.revoked", invite.site.slug, str(invite.id))
    return redirect(url_for("admin_home"))
@app.get("/admin/credits")
@admin_required
def admin_credits():
    payments = CryptoPayment.query.order_by(CryptoPayment.created_at.desc()).limit(500).all()
    ledger = CreditLedger.query.order_by(CreditLedger.created_at.desc()).limit(500).all()
    return render_template_string(CREDITS_HTML, payments=payments, ledger=ledger, csrf=session["csrf"])

@app.get("/admin/order/<int:order_id>/invoice")
@admin_required
def admin_order_invoice(order_id):
    order = db.session.get(StoreOrder, order_id)
    if not order:
        abort(404)
    return render_template_string(INVOICE_HTML, order=order, site=order.site)

@app.get("/setup")
def setup_page():
    if Admin.query.first():
        return "Setup ist bereits abgeschlossen.", 403
    return render_template_string(SETUP_HTML)

@app.post("/setup")
@limiter.limit("3 per hour")
def setup_admin():
    if Admin.query.first():
        return "Setup ist bereits abgeschlossen.", 403
    data = request.get_json(silent=True) or {}
    if not SETUP_TOKEN or not secrets.compare_digest(str(data.get("setup_token", "")), SETUP_TOKEN):
        return jsonify(error="Setup-Token ungültig."), 403
    email = str(data.get("email", "")).strip().lower()
    if not ADMIN_OWNER_EMAIL or email != ADMIN_OWNER_EMAIL:
        return jsonify(error="Die Ersteinrichtung ist ausschließlich für die freigegebene Inhaber-E-Mail erlaubt."), 403
    password = str(data.get("password", ""))
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(password) < 14:
        return jsonify(error="Gültige E-Mail und Passwort mit mindestens 14 Zeichen erforderlich."), 400
    admin = Admin(email=email, password_hash=generate_password_hash(password, method="scrypt"))
    db.session.add(admin)
    db.session.commit()
    return jsonify(ok=True, message="Administrator angelegt. Das Setup-Token danach aus Render entfernen.")



GLOBAL_PORTAL_HTML = r"""<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA · Konto & Websites</title>
<style>
:root{color-scheme:dark;--bg:#070b14;--panel:#111a2c;--line:#293b59;--gold:#e6c77b;--cyan:#72dce8;--muted:#a7b5ca}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 50% -15%,#203858,transparent 55%),var(--bg);color:#f4f7fb;font:15px Inter,system-ui}main{max-width:1120px;margin:0 auto;padding:32px 18px 70px}
header{display:flex;justify-content:space-between;align-items:center;gap:14px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding:18px 0}.brand{color:var(--gold);letter-spacing:.22em;font-size:12px}
h1{font-size:clamp(30px,6vw,54px);margin:10px 0}h2{margin-top:0}.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px}
.card{background:linear-gradient(145deg,#121e32,#0c1423);border:1px solid var(--line);border-radius:18px;padding:22px;margin:16px 0;box-shadow:0 16px 50px #0004}
input,textarea,select{width:100%;margin:7px 0 14px;padding:12px;border-radius:10px;border:1px solid var(--line);background:#081321;color:white}
button,.btn{display:inline-block;padding:11px 16px;border:0;border-radius:10px;background:linear-gradient(100deg,var(--gold),#f5e7ba);color:#171a21;font-weight:750;cursor:pointer;text-decoration:none}
button.secondary,.btn.secondary{background:#1b2a42;color:#eaf5ff;border:1px solid #3b5577}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
small{color:var(--muted)}.status{display:inline-block;padding:4px 9px;border-radius:20px;background:#253650;font-size:12px}
.hidden{display:none!important}.project{border:1px solid var(--line);border-radius:13px;padding:16px;margin:10px 0;background:#0a1424}
a{color:var(--cyan)}.notice{padding:12px;border-radius:10px;background:#14243a;margin:12px 0;white-space:pre-wrap}
</style><style>
/* ULTIMA Network visual refinement: layered glass panels and curved luminous accents */
body{background:radial-gradient(ellipse at 12% 0%,#263d68 0%,transparent 42%),radial-gradient(ellipse at 88% 12%,#3b1d56 0%,transparent 38%),linear-gradient(145deg,#050812,#0b1222 55%,#090714)!important}
main{max-width:1180px!important}
header{position:relative;border-bottom-color:#6077a255!important}
header:after{content:"";position:absolute;left:0;right:0;bottom:-1px;height:1px;background:linear-gradient(90deg,transparent,#e6c77b88,#72dce888,transparent)}
.card{border-radius:22px!important;background:linear-gradient(145deg,#17233bdf,#0d1425ed)!important;border-color:#657ca244!important;box-shadow:0 18px 55px #0005, inset 0 1px #ffffff0b!important;transition:transform .2s ease,border-color .2s ease,box-shadow .2s ease}
.card:hover{transform:translateY(-3px);border-color:#72dce877!important;box-shadow:0 24px 65px #0007,0 0 28px #72dce81c!important}
button,.btn{box-shadow:0 8px 24px #0003;transition:transform .18s ease,filter .18s ease}
button:hover,.btn:hover{transform:translateY(-1px);filter:brightness(1.08)}
input,textarea,select{background:#07101f!important;border-color:#425878!important}
@media(prefers-reduced-motion:reduce){.card,button,.btn{transition:none!important}.card:hover,button:hover,.btn:hover{transform:none!important}}
</style><main><header><div><div class="brand">ULTIMA NETWORK · CENTRAL IDENTITY</div><small>Ein Konto. Deine Profile. Deine Websites.</small><a href="/mentor-chat" style="display:inline-block;margin-left:14px;padding:9px 13px;border:1px solid #e6c77b;border-radius:999px;color:#fff0c6;text-decoration:none;font-weight:700">✦ Mentor-Chat öffnen ↗</a></div><div class="row"><a href="https://ultima-central-45ne.onrender.com/">← Zum Verwaltungszentrum</a><button id="logout" class="secondary hidden">Abmelden</button></div></header>
<section id="auth"><h1>Dein ULTIMA-Konto</h1><p class="muted">Ein zentrales Konto für dein Profil und deine registrierten Webprojekte.</p><div class="grid">
<div class="card"><h2>Konto erstellen</h2><form id="register"><label>Anzeigename</label><input name="display_name" maxlength="120" required><label>Benutzername</label><input name="username" minlength="3" maxlength="32" pattern="[A-Za-z0-9_.-]+" required><label>E-Mail</label><input name="email" type="email" required><label>Passwort (mind. 12 Zeichen)</label><input name="password" type="password" minlength="12" required><button>Konto erstellen</button></form></div>
<div class="card"><h2>Anmelden</h2><form id="login"><label>E-Mail oder Benutzername</label><input name="identity" required><label>Passwort</label><input name="password" type="password" required><button>Anmelden</button></form></div></div></section>
<section id="dashboard" class="hidden"><h1>Dein Profil & Website-Studio</h1><div id="notice" class="notice hidden"></div><div class="grid"><section class="card"><h2>Profil bearbeiten</h2><form id="profile"><label>Anzeigename</label><input name="display_name" maxlength="120"><label>Biografie</label><textarea name="bio" rows="3" maxlength="1000"></textarea><label>Avatar-URL (optional)</label><input name="avatar_url" type="url" maxlength="500"><button>Profil speichern</button></form></section>
<section class="card"><h2>Neue Website eintragen</h2><form id="project"><label>Name</label><input name="name" maxlength="120" required><label>Adresse (HTTPS)</label><input name="url" type="url" placeholder="https://deine-website.de" required><label>Kategorie</label><select name="category"><option>Website</option><option>KI & Technologie</option><option>Shop</option><option>Community</option><option>Kreativprojekt</option><option>Sonstiges</option></select><label>Beschreibung</label><textarea name="description" rows="3" maxlength="2000"></textarea><button>Website speichern</button></form></section></div>
<section class="card" id="premium-card"><h2>ULTIMA Network Premium</h2><p class="muted">Eine Premium-Mitgliedschaft für alle freigeschalteten Websites des Netzwerks. Deine Testphase läuft 7 Tage oder bis zu 25 Premium-Aktionen, je nachdem, was zuerst eintritt.</p><div id="premium-status" class="notice">Premium-Status wird geladen …</div><div id="premium-actions" class="row"></div><div id="premium-invoices"></div><p class="muted">Tarif: 9,99 € für 30 Tage. Kein automatischer Wallet-Einzug. Die Zahlung wird erst nach Prüfung der Bitcoin-Transaktion und zwei Netzwerkbestätigungen freigeschaltet.</p><p class="muted">Premium-Generierungen: erweiterte KI-Modelle, Musik-/Video-/Bild-KI, Spiel- und Mod-Generierung sowie weitere rechenintensive Generatoren. Basiszugriff, Anmeldung und Profilfunktionen bleiben verfügbar.</p></section>
<section class="card"><h2>Meine Websites</h2><p class="muted">Bearbeite deine Einträge und veröffentliche sie im öffentlichen ULTIMA-Verzeichnis.</p><div id="mine"></div></section>
<section class="card"><h2>Öffentliches Website-Verzeichnis</h2><div id="public"></div></section></section>
<script>
const API="";let token=sessionStorage.getItem("ultima_global_token")||"";let me=null;
const $=id=>document.getElementById(id);
function note(msg){$("notice").textContent=msg;$("notice").classList.remove("hidden")}
async function api(path,method="GET",body){const r=await fetch(API+path,{method,headers:{"Content-Type":"application/json",...(token?{Authorization:"Bearer "+token}:{})},...(body?{body:JSON.stringify(body)}:{})});const data=await r.json().catch(()=>({error:"Ungültige Serverantwort"}));if(!r.ok)throw new Error(data.error||"Anfrage fehlgeschlagen");return data}
function formData(form){return Object.fromEntries(new FormData(form).entries())}
function safeText(s){return String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
function projectCard(p,editable){return '<article class="project"><div class="row"><b>'+safeText(p.name)+'</b><span class="status">'+safeText(p.status||'published')+'</span></div><p>'+safeText(p.description)+'</p><p><a href="'+safeText(p.url)+'" target="_blank" rel="noopener noreferrer">'+safeText(p.url)+'</a></p><small>'+safeText(p.category)+'</small>'+(p.slug?'<div class="row" style="margin-top:12px"><button class="secondary" data-sso="'+safeText(p.slug)+'">Mit ULTIMA anmelden ↗</button></div>':'')+(editable?'<div class="row" style="margin-top:12px"><button class="secondary" data-edit="'+p.id+'">Bearbeiten</button><button data-publish="'+p.id+'">'+(p.is_public?'Veröffentlichung aufheben':'Veröffentlichen')+'</button><button class="secondary" data-delete="'+p.id+'">Archivieren</button></div>':'')+'</article>'}
async function refreshPremium(){
 const statusRoot=$("premium-status"),actions=$("premium-actions"),invoicesRoot=$("premium-invoices");
 statusRoot.textContent="Premium-Status wird geladen …";actions.innerHTML="";invoicesRoot.innerHTML="";
 try{
  const d=await api("/api/global/premium/status"),p=d.premium||{};
  let heading=p.status==="lifetime"?"Master Premium · lebenslang aktiv":p.status==="paid"?"Premium aktiv":p.status==="trial"?"Kostenlose Testphase aktiv":p.status==="not_started"?"Testphase noch nicht gestartet":"Testphase beendet";
  statusRoot.innerHTML="<b>"+safeText(heading)+"</b><br>"+(p.status==="trial"?"Verbrauch: "+safeText(p.trial_used)+" / "+safeText(p.trial_limit)+" · verbleibend: "+safeText(p.trial_remaining)+" Aktionen · noch "+safeText(p.trial_days_remaining)+" Tage":p.status==="paid"?"Freigeschaltet bis: "+safeText(p.paid_until||""):"Tarif: "+safeText(p.price_eur||"9.99")+" € / "+safeText(p.period_days||30)+" Tage");
  if(p.status==="not_started"){
   const trial=document.createElement("button");trial.textContent="7-Tage-Testphase starten";trial.onclick=async()=>{trial.disabled=true;try{await api("/api/global/premium/trial/start","POST",{});await refreshPremium()}catch(e){alert(e.message);trial.disabled=false}};actions.append(trial);
  }
  if(p.checkout_ready){
   const buy=document.createElement("button");buy.textContent="Jetzt zahlungspflichtig bestellen · 9,99 €";buy.onclick=async()=>{buy.disabled=true;try{const d=await api("/api/global/premium/invoices","POST",{});await refreshPremium();note("Bitcoin-Rechnung erstellt. Bitte zahle exakt den angezeigten Betrag an die Rechnungwallet.")}catch(e){alert(e.message);buy.disabled=false}};actions.append(buy);
  }else{
   const info=document.createElement("p");info.className="muted";info.textContent="Bitcoin-Checkout ist noch nicht freigeschaltet. Der Betreiber muss die Wallet-Adresse sowie Anbietername, Geschäftsanschrift und öffentliche Vertrags-/Website-Angaben in Render hinterlegen. Bitte noch keine Bitcoin senden.";actions.append(info);
  }
  const items=d.invoices||p.invoices||[];
  items.forEach(x=>{
   const card=document.createElement("article");card.className="project";
   const title=document.createElement("b");title.textContent="Rechnung "+x.invoice_code+" · "+x.amount_eur+" EUR";
   const details=document.createElement("p");details.textContent="Soll: "+x.expected_btc+" BTC · "+x.status+" · Bestätigungen: "+x.confirmations+" · Ablauf: "+x.expires_at;
   card.append(title,details);
   const wallet=document.createElement("p");wallet.style.overflowWrap="anywhere";wallet.textContent="Empfangswallet: "+x.wallet;card.append(wallet);
   if(x.payment_uri){const link=document.createElement("a");link.href=x.payment_uri;link.textContent="Bitcoin-Wallet öffnen";card.append(link)}
   if(x.status!=="paid"&&x.status!=="expired"&&x.status!=="cancelled"){
    const form=document.createElement("form");form.className="row";form.dataset.invoice=x.invoice_code;
    const input=document.createElement("input");input.name="txid";input.placeholder="Bitcoin-TXID (64 Hex-Zeichen)";input.minLength=64;input.maxLength=64;input.required=true;input.style.flex="1 1 360px";
    const submit=document.createElement("button");submit.textContent="TXID prüfen";form.append(input,submit);
    form.onsubmit=async e=>{e.preventDefault();submit.disabled=true;try{const r=await api("/api/global/premium/invoices/"+encodeURIComponent(x.invoice_code)+"/submit","POST",{txid:input.value.trim()});alert(r.result?.message||"Transaktion geprüft.");await refreshPremium()}catch(err){alert(err.message);submit.disabled=false}};
    card.append(form);
   }
   invoicesRoot.append(card);
  });
 }catch(e){statusRoot.textContent="Premium-Status nicht erreichbar: "+e.message}
}
async function refresh(){const data=await api("/api/global/me");me=data.user; $("auth").classList.add("hidden");$("dashboard").classList.remove("hidden");$("logout").classList.remove("hidden");$("profile").elements.display_name.value=me.display_name||"";$("profile").elements.bio.value=me.bio||"";$("profile").elements.avatar_url.value=me.avatar_url||"";const mine=await api("/api/global/projects");$("mine").innerHTML=mine.projects.length?mine.projects.map(p=>projectCard(p,true)).join(""):"<p class='muted'>Noch keine Websites eingetragen.</p>";const pub=await api("/api/global/public-projects");$("public").innerHTML=pub.projects.length?pub.projects.map(p=>projectCard(p,false)).join(""):"<p class='muted'>Noch keine öffentlichen Websites.</p>";await refreshPremium()}
async function maybeSsoRedirect(){
 const siteSlug=new URLSearchParams(location.search).get("site");
 if(!siteSlug||!token)return false;
 const d=await api("/api/global/sso/issue/"+encodeURIComponent(siteSlug),"POST",{});
 if(!d.redirect_url)throw new Error("Single Sign-on konnte für diese Website nicht erstellt werden.");
 location.replace(d.redirect_url);return true;
}
async function authSubmit(form,path){try{const data=await api(path,"POST",formData(form));token=data.token;sessionStorage.setItem("ultima_global_token",token);form.reset();await refresh();if(await maybeSsoRedirect())return;note("Willkommen bei ULTIMA.")}catch(e){alert(e.message)}}
$("register").onsubmit=e=>{e.preventDefault();authSubmit(e.target,"/api/global/register")};
$("login").onsubmit=e=>{e.preventDefault();authSubmit(e.target,"/api/global/login")};
$("profile").onsubmit=async e=>{e.preventDefault();try{await api("/api/global/profile","PATCH",formData(e.target));note("Profil gespeichert.")}catch(err){alert(err.message)}};
$("project").onsubmit=async e=>{e.preventDefault();try{await api("/api/global/projects","POST",formData(e.target));e.target.reset();await refresh();note("Website wurde eingetragen. Du kannst sie jetzt veröffentlichen.")}catch(err){alert(err.message)}};
$("mine").onclick=async e=>{const sso=e.target.dataset.sso,pub=e.target.dataset.publish,edit=e.target.dataset.edit,del=e.target.dataset.delete;try{if(sso){const d=await api("/api/global/sso/issue/"+encodeURIComponent(sso),"POST",{});location.href=d.redirect_url}else if(pub){const p=(await api("/api/global/projects")).projects.find(x=>x.id==pub);await api("/api/global/projects/"+pub,"PATCH",{is_public:!p.is_public});await refresh();note("Veröffentlichungsstatus aktualisiert.")}else if(del){await api("/api/global/projects/"+del,"DELETE");await refresh();note("Website archiviert.")}else if(edit){const p=(await api("/api/global/projects")).projects.find(x=>x.id==edit);const name=prompt("Name",p.name);if(name===null)return;const url=prompt("HTTPS-Adresse",p.url);if(url===null)return;const description=prompt("Beschreibung",p.description);if(description===null)return;await api("/api/global/projects/"+edit,"PATCH",{name,url,description});await refresh();note("Website aktualisiert.")}}catch(err){alert(err.message)}};
$("public").onclick=async e=>{const slug=e.target.dataset.sso;if(!slug)return;try{const d=await api("/api/global/sso/issue/"+encodeURIComponent(slug),"POST",{});location.href=d.redirect_url}catch(err){alert(err.message)}};
$("logout").onclick=()=>{token="";sessionStorage.removeItem("ultima_global_token");$("dashboard").classList.add("hidden");$("auth").classList.remove("hidden");$("logout").classList.add("hidden")};
if(token)refresh().then(()=>maybeSsoRedirect()).catch(e=>{token="";sessionStorage.removeItem("ultima_global_token");if(new URLSearchParams(location.search).get("site"))note(e.message)});
</script></main></html>"""

MENTOR_CHAT_HTML = r"""<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA · Mentorraum</title>
<style>
:root{color-scheme:dark;--bg:#070b14;--panel:#111a2c;--line:#293b59;--gold:#e6c77b;--cyan:#72dce8;--muted:#a7b5ca}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 50% -15%,#203858,transparent 55%),var(--bg);color:#f4f7fb;font:15px Inter,system-ui}main{max-width:1100px;margin:auto;padding:28px 18px 70px}
header{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap;border-bottom:1px solid var(--line);padding:14px 0 20px}
a{color:var(--cyan)}h1{font-size:clamp(28px,5vw,48px);margin:12px 0}h2{margin:0 0 12px}.muted{color:var(--muted)}
.grid{display:grid;grid-template-columns:300px 1fr;gap:16px;margin-top:20px}.card{background:linear-gradient(145deg,#121e32,#0c1423);border:1px solid var(--line);border-radius:18px;padding:18px}
input,textarea,select{width:100%;margin:7px 0 12px;padding:12px;border-radius:10px;border:1px solid var(--line);background:#081321;color:white}
button{padding:10px 14px;border:0;border-radius:10px;background:linear-gradient(100deg,var(--gold),#f5e7ba);color:#171a21;font-weight:750;cursor:pointer}
button.secondary{background:#1b2a42;color:#eaf5ff;border:1px solid #3b5577}
.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.list{display:grid;gap:9px}.entry{padding:12px;border:1px solid var(--line);border-radius:12px;background:#0a1424}.entry button{margin-top:8px}.messages{height:340px;overflow:auto;border:1px solid var(--line);border-radius:12px;padding:12px;background:#081321}.msg{padding:9px 12px;margin:7px 0;border-radius:12px;max-width:85%;background:#1b2a42;white-space:pre-wrap;overflow-wrap:anywhere}.msg.mine{margin-left:auto;background:#263d55}.hidden{display:none!important}.notice{padding:10px 12px;border-radius:10px;background:#14243a;margin:12px 0;white-space:pre-wrap}
@media(max-width:760px){.grid{grid-template-columns:1fr}.messages{height:260px}}
</style><main><header><div><div class="muted">ULTIMA NETWORK · CENTRAL IDENTITY</div><h1>Mentorraum</h1><p class="muted">Stelle eine Anfrage an ein freigegebenes Mentorprofil. Der private Chat wird erst nach Annahme durch den Mentor geöffnet.</p></div><div class="row"><a href="/portal">Profil & Netzwerk ↗</a><a href="https://ate-rea-characterverse.onrender.com">Zur Charakter-KI ↗</a></div></header>
<div id="notice" class="notice">Prüfe deine ULTIMA-Anmeldung …</div><section id="workspace" class="grid hidden">
<aside class="card"><h2>Freigegebene Mentoren</h2><div id="mentors" class="list"></div><h2 style="margin-top:22px">Deine Anfragen</h2><div id="requests" class="list"></div></aside>
<section class="card"><h2 id="chatTitle">Wähle einen Mentor oder eine Unterhaltung</h2><form id="requestForm" class="hidden"><label>Thema</label><input name="topic" maxlength="180" required><label>Nachricht</label><textarea name="message" maxlength="3000" rows="4" required></textarea><button>Anfrage senden</button></form>
<div id="chatArea" class="hidden"><div id="messages" class="messages"></div><form id="sendForm" class="row" style="margin-top:12px"><input name="message" maxlength="4000" placeholder="Nachricht schreiben …" required style="flex:1"><button>Senden</button></form></div></section></section>
<script>
const API="https://ultima-membership-api.onrender.com";const token=sessionStorage.getItem("ultima_global_token");let current=null,mentors=[];
const $=id=>document.getElementById(id);const esc=s=>String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
async function api(path,method="GET",body){const r=await fetch(API+path,{method,headers:{"Content-Type":"application/json","Authorization":"Bearer "+token},body:body?JSON.stringify(body):undefined});const d=await r.json().catch(()=>({}));if(!r.ok)throw Error(d.error||"Anfrage fehlgeschlagen ("+r.status+")");return d}
function note(t){$("notice").textContent=t}
async function refresh(){const d=await api("/api/global/mentors");mentors=d.mentors||[];$("mentors").innerHTML=mentors.length?mentors.map(m=>'<article class="entry"><b>'+esc(m.name)+'</b><p class="muted">'+esc(m.bio||"ULTIMA Mentorprofil")+'</p><button data-mentor="'+m.id+'">Anfrage stellen</button></article>').join(""):'<p class="muted">Aktuell ist noch kein Mentorprofil freigegeben. Der ULTIMA-Inhaber wird angezeigt, sobald sein Netzwerkkonto angelegt ist.</p>';const q=await api("/api/global/mentor-requests");$("requests").innerHTML=(q.requests||[]).map(x=>'<article class="entry"><b>'+esc(x.topic)+'</b><p class="muted">'+esc(x.sender.name)+' → '+esc(x.mentor.name)+' · '+esc(x.status)+'</p>'+(x.status==="pending"&&x.is_mentor?'<button data-accept="'+x.id+'">Anfrage annehmen</button>':'')+(x.status==="accepted"?'<button class="secondary" data-open="'+x.id+'">Chat öffnen</button>':'')+'</article>').join("")||'<p class="muted">Noch keine Anfragen.</p>'}
$("mentors").addEventListener("click",e=>{const b=e.target.closest("[data-mentor]");if(!b)return;const m=mentors.find(x=>x.id===Number(b.dataset.mentor));if(!m)return;current={mentor_id:m.id};$("chatTitle").textContent="Anfrage an "+m.name;$("requestForm").classList.remove("hidden");$("chatArea").classList.add("hidden")});
$("requests").addEventListener("click",async e=>{const a=e.target.closest("[data-accept]"),o=e.target.closest("[data-open]");try{if(a){await api("/api/global/mentor-requests/"+a.dataset.accept+"/accept","POST",{});await refresh();note("Anfrage angenommen. Der private Chat ist freigeschaltet.")}if(o){current={id:Number(o.dataset.open)};$("requestForm").classList.add("hidden");$("chatArea").classList.remove("hidden");await loadMessages()}}catch(err){note(err.message)}});
async function loadMessages(){if(!current?.id)return;const d=await api("/api/global/mentor-requests/"+current.id+"/messages");$("messages").innerHTML=(d.messages||[]).map(m=>'<div class="msg '+(m.sender_id===window.__USER_ID?"mine":"")+'">'+esc(m.body)+'</div>').join("");$("messages").scrollTop=$("messages").scrollHeight}
$("requestForm").onsubmit=async e=>{e.preventDefault();try{const f=e.target;await api("/api/global/mentor-requests","POST",{mentor_id:current.mentor_id,topic:f.topic.value,message:f.message.value});f.reset();f.classList.add("hidden");await refresh();note("Mentor-Anfrage wurde gesendet. Der Chat öffnet sich nach Annahme.")}catch(err){note(err.message)}};
$("sendForm").onsubmit=async e=>{e.preventDefault();try{const f=e.target;await api("/api/global/mentor-requests/"+current.id+"/messages","POST",{message:f.message.value});f.reset();await loadMessages()}catch(err){note(err.message)}};
(async()=>{if(!token){note("Bitte zuerst im ULTIMA-Netzwerk anmelden und danach den Mentorraum erneut öffnen.");return}try{const me=await api("/api/global/me");window.__USER_ID=me.user.id;$("workspace").classList.remove("hidden");await refresh();note("Verbunden mit deinem ULTIMA-Netzwerkprofil.")}catch(e){note(e.message+" · Bitte im Netzwerkportal erneut anmelden.")}})();
</script></main>""" 

@app.get("/mentor-chat")
def mentor_chat_page():
    return render_template_string(MENTOR_CHAT_HTML)

@app.get("/portal")
def global_portal():
    return render_template_string(GLOBAL_PORTAL_HTML)

@app.post("/api/global/register")
@limiter.limit("5 per hour")
def global_register():
    data = request.get_json(silent=True) or {}
    email = str(data.get("email", "")).strip().lower()
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))
    display_name = str(data.get("display_name", username)).strip()[:120]
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 255:
        return jsonify(error="Bitte eine gültige E-Mail-Adresse eingeben."), 400
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        return jsonify(error="Benutzername: 3–32 Zeichen, Buchstaben, Zahlen, Punkt, _ oder -."), 400
    if len(password) < 12 or len(password) > 128:
        return jsonify(error="Das Passwort muss 12 bis 128 Zeichen lang sein."), 400
    if GlobalUser.query.filter(func.lower(GlobalUser.email) == email).first():
        return jsonify(error="Diese E-Mail ist bereits registriert."), 409
    if GlobalUser.query.filter(func.lower(GlobalUser.username) == username.lower()).first():
        return jsonify(error="Dieser Benutzername ist bereits vergeben."), 409
    role = "owner" if ADMIN_OWNER_EMAIL and email == ADMIN_OWNER_EMAIL else "member"
    user = GlobalUser(email=email, username=username, password_hash=generate_password_hash(password, method="scrypt"), display_name=display_name, role=role)
    db.session.add(user)
    db.session.flush()
    if role == "owner":
        existing_admin = Admin.query.filter(func.lower(Admin.email) == email).first()
        if not existing_admin:
            db.session.add(Admin(email=email, password_hash=user.password_hash, role="superadmin"))
        else:
            existing_admin.role = "superadmin"
        registry_path = os.path.join(os.path.dirname(__file__), "sites.json")
        excluded = ("lyca", "bullrun", "roth", "royal-palace", "business-real-estate")
        if os.path.exists(registry_path):
            with open(registry_path, "r", encoding="utf-8") as registry_file:
                for item in json.load(registry_file):
                    slug = str(item.get("slug", "")).lower()
                    if not item.get("is_active", True) or not item.get("membership_enabled", True) or any(term in slug for term in excluded):
                        continue
                    project_url = clean_project_url(item.get("origin"))
                    if not project_url or WebsiteProject.query.filter_by(slug=slug).first():
                        continue
                    db.session.add(WebsiteProject(owner_id=user.id, name=str(item.get("name", slug))[:120], slug=slug,
                        url=project_url, description="Aus dem bestehenden ULTIMA-Website-Verzeichnis übernommen.",
                        category="Website", status="draft", is_public=False))
    db.session.commit()
    audit("global:" + email, "global.register", None, str(user.id))
    return jsonify(ok=True, token=issue_global_token(user), user={"id": user.id, "email": user.email, "username": user.username, "display_name": user.display_name, "role": user.role}), 201

@app.post("/api/global/login")
@limiter.limit("10 per 15 minutes")
def global_login():
    data = request.get_json(silent=True) or {}
    identity = str(data.get("identity", "")).strip()
    password = str(data.get("password", ""))
    if not identity or not password:
        return jsonify(error="E-Mail/Benutzername und Passwort werden benötigt."), 400

    user = GlobalUser.query.filter(func.lower(GlobalUser.email) == identity.lower()).first()
    if not user:
        user = GlobalUser.query.filter(func.lower(GlobalUser.username) == identity.lower()).first()

    valid_global = bool(user and user.status == "active" and check_password_hash(user.password_hash, password))

    # Compatibility bridge for older ULTIMA owner accounts. Older installations
    # stored the owner hash in Admin, while the new portal authenticates GlobalUser.
    # A successful password check is required before linking; no password is reset.
    if not valid_global and ADMIN_OWNER_EMAIL and identity.lower() == ADMIN_OWNER_EMAIL:
        legacy_admin = Admin.query.filter(func.lower(Admin.email) == ADMIN_OWNER_EMAIL).first()
        if legacy_admin and check_password_hash(legacy_admin.password_hash, password):
            if not user:
                base = re.sub(r"[^A-Za-z0-9_.-]", "", ADMIN_OWNER_EMAIL.split("@", 1)[0])[:32] or "ultima-owner"
                base = base if len(base) >= 3 else (base + "-owner")[:32]
                username = base
                suffix = 2
                while GlobalUser.query.filter(func.lower(GlobalUser.username) == username.lower()).first():
                    tail = "-" + str(suffix)
                    username = base[:32-len(tail)] + tail
                    suffix += 1
                user = GlobalUser(email=ADMIN_OWNER_EMAIL, username=username,
                    password_hash=legacy_admin.password_hash, display_name=username,
                    role="owner", status="active")
                db.session.add(user)
            else:
                user.password_hash = legacy_admin.password_hash
                user.role = "owner"
                user.status = "active"
                user.token_version += 1
            legacy_admin.role = "superadmin"
            db.session.commit()
            valid_global = True

    if not valid_global:
        return jsonify(error="Anmeldedaten ungültig oder Konto gesperrt."), 401

    audit("global:" + user.email, "global.login", None, str(user.id))
    return jsonify(ok=True, token=issue_global_token(user), user={"id": user.id, "email": user.email, "username": user.username, "display_name": user.display_name, "role": user.role})

@app.get("/api/global/me")
def global_me():
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    return jsonify(user={"id": user.id, "email": user.email, "username": user.username, "display_name": user.display_name, "bio": user.bio, "avatar_url": user.avatar_url, "role": user.role, "created_at": user.created_at.isoformat()})

@app.patch("/api/global/profile")
def global_profile_update():
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    data = request.get_json(silent=True) or {}
    if "display_name" in data:
        user.display_name = str(data["display_name"]).strip()[:120]
    if "bio" in data:
        user.bio = str(data["bio"]).strip()[:1000]
    if "avatar_url" in data:
        avatar = str(data["avatar_url"]).strip()
        if avatar and not clean_project_url(avatar):
            return jsonify(error="Avatar muss eine gültige HTTPS-Adresse sein."), 400
        user.avatar_url = avatar[:500]
    db.session.commit()
    audit("global:" + user.email, "global.profile.update", None, str(user.id))
    return jsonify(ok=True)

@app.get("/api/global/projects")
def global_projects_list():
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    projects = WebsiteProject.query.filter_by(owner_id=user.id).order_by(WebsiteProject.updated_at.desc()).all()
    return jsonify(projects=[project_payload(p) for p in projects])

@app.post("/api/global/projects")
@limiter.limit("20 per hour")
def global_projects_create():
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()[:120]
    url = clean_project_url(data.get("url"))
    description = str(data.get("description", "")).strip()[:2000]
    category = str(data.get("category", "Website")).strip()[:60] or "Website"
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:54]
    if len(name) < 3 or not url or len(slug) < 3:
        return jsonify(error="Bitte einen Namen (mindestens 3 Zeichen) und eine gültige HTTPS-Adresse angeben."), 400
    base, suffix = slug, 2
    while WebsiteProject.query.filter_by(slug=slug).first():
        slug = f"{base[:58]}-{suffix}"
        suffix += 1
    project = WebsiteProject(owner_id=user.id, name=name, slug=slug, url=url, description=description, category=category, status="draft", is_public=False)
    db.session.add(project)
    db.session.commit()
    audit("global:" + user.email, "project.create", slug, url)
    return jsonify(ok=True, project=project_payload(project)), 201

@app.patch("/api/global/projects/<int:project_id>")
def global_projects_update(project_id):
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    project = WebsiteProject.query.filter_by(id=project_id, owner_id=user.id).first()
    if not project:
        return jsonify(error="Website nicht gefunden."), 404
    data = request.get_json(silent=True) or {}
    if "name" in data:
        name = str(data["name"]).strip()[:120]
        if len(name) < 3:
            return jsonify(error="Der Name muss mindestens 3 Zeichen lang sein."), 400
        project.name = name
    if "url" in data:
        url = clean_project_url(data["url"])
        if not url:
            return jsonify(error="Bitte eine gültige HTTPS-Adresse angeben."), 400
        project.url = url
    if "description" in data:
        project.description = str(data["description"]).strip()[:2000]
    if "category" in data:
        project.category = str(data["category"]).strip()[:60] or "Website"
    if "is_public" in data:
        project.is_public = bool(data["is_public"])
        project.status = "published" if project.is_public else "draft"
    db.session.commit()
    audit("global:" + user.email, "project.update", project.slug, str(project.id))
    return jsonify(ok=True, project=project_payload(project))

@app.delete("/api/global/projects/<int:project_id>")
def global_projects_archive(project_id):
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    project = WebsiteProject.query.filter_by(id=project_id, owner_id=user.id).first()
    if not project:
        return jsonify(error="Website nicht gefunden."), 404
    project.status = "archived"
    project.is_public = False
    db.session.commit()
    audit("global:" + user.email, "project.archive", project.slug, str(project.id))
    return jsonify(ok=True)

@app.get("/api/global/public-projects")
def global_public_projects():
    projects = WebsiteProject.query.filter_by(is_public=True, status="published").order_by(WebsiteProject.updated_at.desc()).limit(500).all()
    return jsonify(projects=[{"id": p.id, "name": p.name, "slug": p.slug, "url": p.url, "description": p.description, "category": p.category, "owner": p.owner.display_name or p.owner.username, "status": p.status} for p in projects])


def mentor_request_payload(item, viewer_id):
    sender = db.session.get(GlobalUser, item.sender_id)
    mentor = db.session.get(GlobalUser, item.mentor_id)
    return {
        "id": item.id, "topic": item.topic, "opening_message": item.opening_message,
        "status": item.status, "created_at": item.created_at.isoformat(),
        "is_mentor": viewer_id == item.mentor_id,
        "sender": {"id": sender.id, "name": sender.display_name or sender.username, "username": sender.username} if sender else None,
        "mentor": {"id": mentor.id, "name": mentor.display_name or mentor.username, "username": mentor.username} if mentor else None
    }

@app.get("/api/global/mentors")
@limiter.limit("60 per hour")
def global_mentors():
    viewer = current_global_user()
    if not viewer:
        return jsonify(error="Bitte zuerst im ULTIMA-Netzwerk anmelden."), 401
    mentors = GlobalUser.query.filter(
        GlobalUser.status == "active",
        ((GlobalUser.role == "mentor") | (func.lower(GlobalUser.email) == ADMIN_OWNER_EMAIL))
    ).order_by(GlobalUser.display_name.asc()).limit(100).all()
    return jsonify(mentors=[{"id": m.id, "name": m.display_name or m.username, "username": m.username,
                             "bio": m.bio, "avatar_url": m.avatar_url,
                             "is_owner": bool(ADMIN_OWNER_EMAIL and m.email.lower() == ADMIN_OWNER_EMAIL)}
                            for m in mentors])

@app.post("/api/global/mentor-requests")
@limiter.limit("10 per hour")
def global_mentor_request_create():
    viewer = current_global_user()
    if not viewer:
        return jsonify(error="Bitte zuerst im ULTIMA-Netzwerk anmelden."), 401
    data = request.get_json(silent=True) or {}
    try:
        mentor_id = int(data.get("mentor_id"))
    except (TypeError, ValueError):
        return jsonify(error="Bitte einen Mentor auswählen."), 400
    topic = str(data.get("topic", "")).strip()
    opening = str(data.get("message", "")).strip()
    if not topic or len(topic) > 180 or not opening or len(opening) > 3000:
        return jsonify(error="Thema (max. 180 Zeichen) und Nachricht (max. 3000 Zeichen) sind erforderlich."), 400
    mentor = db.session.get(GlobalUser, mentor_id)
    allowed_mentor = bool(mentor and mentor.status == "active" and (
        mentor.role == "mentor" or (ADMIN_OWNER_EMAIL and mentor.email.lower() == ADMIN_OWNER_EMAIL)
    ))
    if not allowed_mentor:
        return jsonify(error="Dieses Profil ist derzeit nicht als Mentor freigegeben."), 403
    if mentor.id == viewer.id:
        return jsonify(error="Du kannst keine Mentor-Anfrage an dein eigenes Profil senden."), 400
    item = MentorRequest(sender_id=viewer.id, mentor_id=mentor.id, topic=topic, opening_message=opening, status="pending")
    db.session.add(item)
    db.session.commit()
    audit("global:" + viewer.email, "mentor.request.created", None, str(item.id))
    return jsonify(ok=True, request=mentor_request_payload(item, viewer.id)), 201

@app.get("/api/global/mentor-requests")
@limiter.limit("60 per hour")
def global_mentor_requests():
    viewer = current_global_user()
    if not viewer:
        return jsonify(error="Bitte zuerst im ULTIMA-Netzwerk anmelden."), 401
    items = MentorRequest.query.filter(
        (MentorRequest.sender_id == viewer.id) | (MentorRequest.mentor_id == viewer.id)
    ).order_by(MentorRequest.updated_at.desc()).limit(100).all()
    return jsonify(requests=[mentor_request_payload(item, viewer.id) for item in items])

@app.post("/api/global/mentor-requests/<int:request_id>/accept")
@limiter.limit("30 per hour")
def global_mentor_request_accept(request_id):
    viewer = current_global_user()
    if not viewer:
        return jsonify(error="Bitte zuerst im ULTIMA-Netzwerk anmelden."), 401
    item = db.session.get(MentorRequest, request_id)
    if not item or item.mentor_id != viewer.id:
        return jsonify(error="Mentor-Anfrage nicht gefunden."), 404
    if item.status != "pending":
        return jsonify(error="Diese Anfrage wurde bereits bearbeitet."), 409
    item.status = "accepted"
    item.updated_at = datetime.now(timezone.utc)
    db.session.commit()
    audit("global:" + viewer.email, "mentor.request.accepted", None, str(item.id))
    return jsonify(ok=True, request=mentor_request_payload(item, viewer.id))

@app.get("/api/global/mentor-requests/<int:request_id>/messages")
@limiter.limit("120 per hour")
def global_mentor_messages(request_id):
    viewer = current_global_user()
    if not viewer:
        return jsonify(error="Bitte zuerst im ULTIMA-Netzwerk anmelden."), 401
    item = db.session.get(MentorRequest, request_id)
    if not item or viewer.id not in (item.sender_id, item.mentor_id):
        return jsonify(error="Unterhaltung nicht gefunden."), 404
    if item.status != "accepted":
        return jsonify(error="Der Chat wird erst nach beidseitiger Annahme freigeschaltet."), 403
    messages = MentorMessage.query.filter_by(request_id=item.id).order_by(MentorMessage.created_at.asc()).limit(300).all()
    return jsonify(messages=[{"id": m.id, "sender_id": m.sender_id, "body": m.body, "created_at": m.created_at.isoformat()} for m in messages])

@app.post("/api/global/mentor-requests/<int:request_id>/messages")
@limiter.limit("60 per hour")
def global_mentor_message_send(request_id):
    viewer = current_global_user()
    if not viewer:
        return jsonify(error="Bitte zuerst im ULTIMA-Netzwerk anmelden."), 401
    item = db.session.get(MentorRequest, request_id)
    if not item or viewer.id not in (item.sender_id, item.mentor_id):
        return jsonify(error="Unterhaltung nicht gefunden."), 404
    if item.status != "accepted":
        return jsonify(error="Der Chat wird erst nach Annahme der Mentor-Anfrage freigeschaltet."), 403
    data = request.get_json(silent=True) or {}
    body = str(data.get("message", "")).strip()
    if not body or len(body) > 4000:
        return jsonify(error="Nachricht muss zwischen 1 und 4000 Zeichen lang sein."), 400
    msg = MentorMessage(request_id=item.id, sender_id=viewer.id, body=body)
    item.updated_at = datetime.now(timezone.utc)
    db.session.add(msg)
    db.session.commit()
    return jsonify(ok=True, message={"id": msg.id, "sender_id": msg.sender_id, "body": msg.body, "created_at": msg.created_at.isoformat()}), 201

@app.get("/api/global/premium/status")
def global_premium_status():
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    status = premium_status_payload(user.email)
    invoices = NetworkPremiumInvoice.query.filter(func.lower(NetworkPremiumInvoice.email) == user.email.lower()).order_by(NetworkPremiumInvoice.created_at.desc()).limit(10).all()
    status["invoices"] = [premium_invoice_payload(x) for x in invoices]
    return jsonify(premium=status)

@app.post("/api/global/premium/trial/start")
@limiter.limit("3 per hour")
def global_premium_start_trial():
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    return jsonify(ok=True,premium=premium_status_payload(user.email,start_trial=True))

@app.get("/api/global/premium/invoices")
def global_premium_invoices():
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    rows = NetworkPremiumInvoice.query.filter(func.lower(NetworkPremiumInvoice.email) == user.email.lower()).order_by(NetworkPremiumInvoice.created_at.desc()).limit(20).all()
    return jsonify(invoices=[premium_invoice_payload(x) for x in rows])

@app.post("/api/global/premium/invoices")
@limiter.limit("3 per hour")
def global_premium_invoice_create():
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    try:
        invoice = create_network_premium_invoice(user.email, "ultima-network")
    except Exception as exc:
        app.logger.warning("Global premium invoice creation unavailable: %s", type(exc).__name__)
        return jsonify(error=str(exc)[:300]), 503
    return jsonify(ok=True,invoice=invoice),201

@app.post("/api/global/premium/invoices/<invoice_code>/submit")
@limiter.limit("10 per hour")
def global_premium_invoice_submit(invoice_code):
    user = current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."), 401
    invoice = NetworkPremiumInvoice.query.filter_by(invoice_code=invoice_code,email=user.email.lower()).first()
    if not invoice:
        return jsonify(error="Premium-Rechnung nicht gefunden."),404
    if invoice.status == "paid":
        return jsonify(ok=True,result={"status":"paid","paid_until":invoice.paid_until.isoformat() if invoice.paid_until else None})
    if invoice.expires_at <= datetime.now(timezone.utc) and not invoice.txid:
        invoice.status="expired";db.session.commit()
        return jsonify(error="Diese Rechnung ist abgelaufen. Bitte eine neue Rechnung erstellen."),410
    data=request.get_json(silent=True) or {}
    try:
        result=verify_network_premium_invoice(invoice,data.get("txid"))
    except Exception as exc:
        app.logger.info("Global premium TXID verification rejected: %s",type(exc).__name__)
        return jsonify(error=str(exc)[:300]),400
    return jsonify(ok=True,result=result,premium=premium_status_payload(user.email))

@app.post("/api/global/premium/cancel")
def global_premium_cancel():
    user=current_global_user()
    if not user:
        return jsonify(error="Anmeldung erforderlich."),401
    account=premium_account_for(user.email)
    account.renewal_disabled=True
    db.session.commit()
    return jsonify(ok=True,paid_until=account.paid_until.isoformat() if account.paid_until else None,
        message="Es gibt keine automatische Wallet-Abbuchung. Dein vorausbezahlter Zugang bleibt bis zum Ablauf aktiv.")

@app.post("/api/global/sso/issue/<slug>")
@limiter.limit("20 per hour")
def global_sso_issue(slug):
    user = current_global_user()
    if not user:
        return jsonify(error="Bitte zuerst beim zentralen ULTIMA-Konto anmelden."), 401
    site = Site.query.filter_by(slug=slug, is_active=True, membership_enabled=True).first()
    if not site:
        return jsonify(error="Diese Website ist noch nicht für ULTIMA Single Sign-on freigeschaltet."), 404
    raw_code = secrets.token_urlsafe(32)
    row = GlobalSSOCode(code_hash=hashlib.sha256(raw_code.encode("utf-8")).hexdigest(),
        user_id=user.id, site_id=site.id, expires_at=datetime.now(timezone.utc) + timedelta(minutes=2))
    db.session.add(row)
    db.session.commit()
    audit("global:" + user.email, "global.sso.issue", site.slug, str(row.id))
    return jsonify(ok=True, redirect_url=site.origin.rstrip("/") + "/?ultima_sso=" + raw_code)

@app.post("/api/global/sso/exchange")
@limiter.limit("30 per hour")
def global_sso_exchange():
    data = request.get_json(silent=True) or {}
    raw_code = str(data.get("code", "")).strip()
    slug = str(data.get("slug", "")).strip().lower()
    if not raw_code or not slug or len(raw_code) > 160:
        return jsonify(error="SSO-Code oder Website-Kennung fehlt."), 400
    digest = hashlib.sha256(raw_code.encode("utf-8")).hexdigest()
    code = GlobalSSOCode.query.filter_by(code_hash=digest).with_for_update().first()
    now = datetime.now(timezone.utc)
    if not code or code.used_at or code.expires_at <= now:
        return jsonify(error="Der einmalige ULTIMA-Anmeldelink ist ungültig oder abgelaufen. Bitte erneut anmelden."), 401
    site = db.session.get(Site, code.site_id)
    user = db.session.get(GlobalUser, code.user_id)
    if not site or site.slug != slug or not site.is_active or not site.membership_enabled or not user or user.status != "active":
        return jsonify(error="Website oder ULTIMA-Konto ist nicht freigeschaltet."), 403
    member = Member.query.filter(func.lower(Member.email) == user.email.lower(), Member.site_id == site.id).first()
    if member and member.status != "active":
        return jsonify(error="Das lokale Konto wartet noch auf Freigabe oder ist gesperrt."), 403
    if not member:
        base = user.username[:32]
        username = base
        suffix = 2
        while Member.query.filter_by(site_id=site.id, username=username).first():
            tail = "-" + str(suffix)
            username = base[:32-len(tail)] + tail
            suffix += 1
        is_owner = user.role == "owner" or (ADMIN_OWNER_EMAIL and user.email.lower() == ADMIN_OWNER_EMAIL)
        member = Member(site_id=site.id, email=user.email, username=username,
            password_hash=generate_password_hash(secrets.token_urlsafe(32), method="scrypt"),
            display_name=user.display_name or user.username,
            role="superadmin" if is_owner else "member", status="active",
            is_lifetime_premium=bool(is_owner or (PREMIUM_OWNER_EMAIL and user.email.lower() == PREMIUM_OWNER_EMAIL)))
        db.session.add(member)
    elif user.role == "owner" or (ADMIN_OWNER_EMAIL and user.email.lower() == ADMIN_OWNER_EMAIL):
        member.role = "superadmin"
        member.status = "active"
        member.is_lifetime_premium = True
        member.token_version += 1
    code.used_at = now
    db.session.commit()
    audit("global:" + user.email, "global.sso.exchange", site.slug, str(member.id))
    return jsonify(ok=True, token=issue_token(member), site={"slug": site.slug, "name": site.name},
        member={"id": member.id, "email": member.email, "username": member.username, "display_name": member.display_name, "role": member.role})

@app.get("/admin/website-projects")
@admin_required
def admin_website_projects():
    projects = WebsiteProject.query.order_by(WebsiteProject.updated_at.desc()).limit(500).all()
    return render_template_string("""<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><body style="background:#080b14;color:#edf1ff;font:15px system-ui;padding:24px"><h1>ULTIMA · Website-Projekte</h1><p><a href="/admin">← Control Center</a></p>{% for p in projects %}<section style="padding:16px;margin:12px 0;background:#11182a;border:1px solid #26304a;border-radius:12px"><b>{{p.name}}</b> · {{p.status}} · {{p.owner.email}}<p>{{p.url}}</p><p>{{p.description}}</p><form method="post" action="/admin/website-projects/{{p.id}}"><input type="hidden" name="csrf" value="{{csrf}}"><button name="action" value="publish">Veröffentlichen</button><button name="action" value="hide">Ausblenden</button><button name="action" value="archive">Archivieren</button></form></section>{% endfor %}</body>""", projects=projects, csrf=session["csrf"])

@app.post("/admin/website-projects/<int:project_id>")
@admin_required
def admin_website_project_action(project_id):
    if not admin_csrf_ok():
        abort(400)
    project = db.session.get(WebsiteProject, project_id)
    if not project:
        abort(404)
    action = request.form.get("action")
    if action == "publish":
        project.is_public = True
        project.status = "published"
    elif action == "hide":
        project.is_public = False
        project.status = "draft"
    elif action == "archive":
        project.is_public = False
        project.status = "archived"
    else:
        abort(400)
    db.session.commit()
    audit("admin", "project." + action, project.slug, str(project.id))
    return redirect(url_for("admin_website_projects"))


@app.get("/admin/login")
def admin_login():
    return render_template_string(LOGIN_HTML)

@app.post("/admin/login")
@limiter.limit("5 per 15 minutes")
def admin_login_post():
    data = request.form
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")
    if not ADMIN_OWNER_EMAIL or email != ADMIN_OWNER_EMAIL:
        return render_template_string(LOGIN_HTML, error="Dieses Konto ist nicht als alleiniger ULTIMA-Inhaber freigegeben."), 401

    # Central ULTIMA login is independent of every excluded property.
    admin = Admin.query.filter(func.lower(Admin.email) == email).first()

    if not admin or not check_password_hash(admin.password_hash, password):
        return render_template_string(LOGIN_HTML, error="Anmeldedaten ungültig. Nutze dein eingerichtetes ULTIMA-Admin-Konto."), 401

    session.clear()
    session["admin_id"] = admin.id
    session["admin_email"] = admin.email
    session["csrf"] = secrets.token_urlsafe(32)
    session["admin_auth_at"] = datetime.now(timezone.utc).timestamp()
    session["admin_last_seen"] = session["admin_auth_at"]
    admin.role = "superadmin"
    db.session.commit()
    session.permanent = True
    audit("admin:" + admin.email, "admin.login")
    return redirect(url_for("admin_home"))

@app.post("/admin/logout")
@admin_required
def admin_logout():
    if not admin_csrf_ok():
        abort(400)
    session.clear()
    return redirect(url_for("admin_login"))

PREMIUM_PRICE_EUR = Decimal("29.99")

def send_premium_email(to_email, subject, body):
    host = os.getenv("SMTP_HOST", "").strip()
    user = os.getenv("SMTP_USER", "").strip()
    password = os.getenv("SMTP_PASSWORD", "")
    sender = os.getenv("SMTP_FROM", user).strip()
    if not all((host, user, password, sender, to_email)):
        app.logger.warning("Premium email not sent: SMTP configuration incomplete")
        return False
    from email.message import EmailMessage
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = to_email
    message.set_content(body)
    try:
        with smtplib.SMTP(host, int(os.getenv("SMTP_PORT", "587")), timeout=15) as smtp:
            smtp.starttls()
            smtp.login(user, password)
            smtp.send_message(message)
        return True
    except Exception as exc:
        app.logger.warning("Premium email failed: %s", type(exc).__name__)
        return False

@app.post("/api/premium/applications")
@limiter.limit("5 per hour")
def premium_application_create():
    data = request.get_json(silent=True) or {}
    name = str(data.get("name", "")).strip()[:160]
    email = str(data.get("email", "")).strip().lower()
    website = str(data.get("website_url", "")).strip()
    details = str(data.get("details", "")).strip()[:2000]
    parsed = urlparse(website)
    if not name or not re.fullmatch(r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+", email) or len(email) > 255:
        return jsonify(error="Bitte Name und gültige E-Mail-Adresse angeben."), 400
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return jsonify(error="Bitte eine gültige HTTPS-Webseitenadresse angeben."), 400
    if PremiumApplication.query.filter_by(email=email, website_url=website).filter(PremiumApplication.status.in_(["pending","approved","checkout","active"])).first():
        return jsonify(error="Für diese E-Mail und Webseite besteht bereits ein Antrag."), 409
    application = PremiumApplication(name=name,email=email,website_url=website,details=details)
    db.session.add(application)
    db.session.commit()
    admin_url = os.getenv("ULTIMA_PUBLIC_URL", request.url_root.rstrip("/")).rstrip("/") + "/admin/premium"
    owner_sent = send_premium_email(ADMIN_OWNER_EMAIL, "ULTIMA Premium-Antrag wartet auf Freigabe", f"Neuer Antrag #{application.id}\\nName: {name}\\nE-Mail: {email}\\nWebseite: {website}\\nDetails: {details}\\n\\nBitte anmelden und Antrag prüfen: {admin_url}")
    send_premium_email(email, "ULTIMA Premium-Antrag eingegangen", f"Hallo {name},\\n\\nDein Antrag für ULTIMA Premium (29,99 EUR monatlich) ist eingegangen. Nach Prüfung durch den Betreiber erhältst du den Zahlungslink.\\n\\nDein ULTIMA-Team")
    audit("premium-applicant:" + email, "premium.application_submitted", None, str(application.id))
    return jsonify(ok=True, application_id=application.id, status="pending", owner_notification_sent=owner_sent, message="Antrag eingegangen. Du erhältst nach der Betreiberfreigabe eine E-Mail mit dem sicheren Checkout-Link."), 201

@app.get("/admin/premium")
@admin_required
def admin_premium():
    applications = PremiumApplication.query.order_by(PremiumApplication.created_at.desc()).limit(300).all()
    accounts = NetworkPremiumAccount.query.order_by(NetworkPremiumAccount.updated_at.desc()).limit(500).all()
    invoices = NetworkPremiumInvoice.query.order_by(NetworkPremiumInvoice.created_at.desc()).limit(300).all()
    active_accounts = sum(1 for a in accounts if (a.paid_until and a.paid_until > datetime.now(timezone.utc)) or (a.trial_ends_at and a.trial_ends_at > datetime.now(timezone.utc) and a.trial_used < a.trial_limit))
    return render_template_string("""<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA Network Premium</title><style>
body{background:#080b14;color:#edf1ff;font:15px system-ui;padding:24px;max-width:1250px;margin:auto}a{color:#8ce4f0}.card{background:#11182a;border:1px solid #26304a;border-radius:14px;padding:16px;margin:12px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.stat{font-size:25px;font-weight:800;color:#e8ce8d}button{padding:10px;background:#293b68;color:white;border:0;border-radius:8px;cursor:pointer}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #293650;text-align:left;vertical-align:top}code{overflow-wrap:anywhere}.muted{color:#a8b4cd}
</style><h1>ULTIMA Network Premium · Verwaltungscenter</h1><p><a href="/admin">← Control Center</a> · <a href="/portal">Zentrales Mitgliederportal ↗</a></p>
<div class="grid"><section class="card"><small>PREMIUM-KONTEN</small><div class="stat">{{accounts|length}}</div></section><section class="card"><small>DERZEIT AKTIV</small><div class="stat">{{active_accounts}}</div></section><section class="card"><small>OFFENE BTC-RECHNUNGEN</small><div class="stat">{{pending_invoices}}</div></section><section class="card"><small>TESTPHASE</small><div class="stat">{{trial_days}} Tage · {{trial_uses}} Nutzungen</div></section></div>
<section class="card"><h2>Einheitlicher Netzwerktarif</h2><p><b>{{price}} EUR / {{period_days}} Tage</b> · {{trial_days}} Tage kostenlose Testphase oder bis zu {{trial_uses}} Premium-Aktionen (je nachdem, was zuerst erreicht wird).</p><p>Die Verlängerung erfolgt nicht automatisch. Nutzer senden Bitcoin an die konfigurierte Wallet; das System prüft TXID, Empfangsadresse, Betrag und Bestätigungen. Premium wird erst nach {{required_confirmations}} Bitcoin-Bestätigungen freigeschaltet.</p><p>Wallet: <b>{{wallet or "Nicht konfiguriert"}}</b> · {{network}} · Checkout: <b>{{"bereit" if checkout_ready else "deaktiviert – Anbieter-/Walletdaten prüfen"}}</b></p><p class="muted">Produktiv-Checkout bleibt gesperrt, bis die Empfangsadresse und Anbieterangaben (Name, Anschrift, öffentliche URL) als Render-Secrets gesetzt sind.</p></section>
<section class="card"><h2>Netzwerk-Premium-Mitglieder</h2><table><tr><th>E-Mail</th><th>Testverbrauch</th><th>Testphase bis</th><th>Bezahlt bis</th><th>Verlängerung</th></tr>{% for a in accounts %}<tr><td>{{a.email}}</td><td>{{a.trial_used}} / {{a.trial_limit}}</td><td>{{a.trial_ends_at or "Noch nicht gestartet"}}</td><td>{{a.paid_until or "—"}}</td><td>{{"Aus" if a.renewal_disabled else "Ein"}}</td></tr>{% else %}<tr><td colspan="5">Noch keine Premium-Konten angelegt.</td></tr>{% endfor %}</table></section>
<section class="card"><h2>Bitcoin-Rechnungen / TXID-Prüfung</h2><table><tr><th>Datum</th><th>Konto</th><th>Rechnung</th><th>Betrag</th><th>TXID</th><th>Status</th><th>Aktion</th></tr>{% for x in invoices %}<tr><td>{{x.created_at}}</td><td>{{x.email}}<br><small>{{x.site_slug}}</small></td><td>{{x.invoice_code}}</td><td>{{x.amount_eur}} EUR<br>{{x.expected_sats}} sats</td><td><code>{{x.txid or "Noch nicht eingereicht"}}</code></td><td>{{x.status}} · {{x.confirmations}} conf.</td><td>{% if x.txid and x.status != "paid" %}<form method="post" action="/admin/premium/bitcoin/{{x.id}}/verify"><input type="hidden" name="csrf" value="{{csrf}}"><button>Blockchain erneut prüfen</button></form>{% endif %}</td></tr>{% else %}<tr><td colspan="7">Keine Rechnungen vorhanden.</td></tr>{% endfor %}</table></section>
<section class="card"><h2>Frühere Premium-Anträge (legacy)</h2>{% for a in applications %}<p>#{{a.id}} · {{a.name}} · {{a.email}} · {{a.status}} · {{a.website_url}}{% if a.checkout_url %} · <a href="{{a.checkout_url}}">Checkout</a>{% endif %}</p>{% else %}<p>Keine alten Anträge.</p>{% endfor %}</section></html>""",
        applications=applications,accounts=accounts,invoices=invoices,active_accounts=active_accounts,
        pending_invoices=sum(1 for x in invoices if x.status in ("pending","confirming","awaiting_confirmations")),
        trial_days=PREMIUM_TRIAL_DAYS,trial_uses=PREMIUM_TRIAL_USES,price=UNIFIED_PREMIUM_PRICE_EUR,
        period_days=PREMIUM_PERIOD_DAYS,required_confirmations=PREMIUM_CONFIRMATIONS_REQUIRED,
        wallet=BTC_ADDRESS,network=BTC_NETWORK,checkout_ready=premium_checkout_ready(),csrf=session["csrf"])

@app.post("/admin/premium/bitcoin/<int:invoice_id>/verify")
@admin_required
def admin_premium_bitcoin_verify(invoice_id):
    if not admin_csrf_ok():
        abort(400)
    invoice=db.session.get(NetworkPremiumInvoice,invoice_id)
    if not invoice or not invoice.txid:
        abort(404)
    try:
        verify_network_premium_invoice(invoice,invoice.txid)
        audit("admin:"+session.get("admin_email",ADMIN_OWNER_EMAIL),"premium.bitcoin.verify",None,str(invoice.id))
    except Exception as exc:
        app.logger.warning("Admin BTC verification failed: %s",type(exc).__name__)
    return redirect(url_for("admin_premium"))

@app.post("/admin/premium/<int:application_id>/<action>")
@admin_required
def admin_premium_decision(application_id, action):
    if not admin_csrf_ok():
        abort(400)
    application = db.session.get(PremiumApplication, application_id)
    if not application or application.status != "pending":
        abort(404)
    if action == "reject":
        application.status = "rejected"
        db.session.commit()
        send_premium_email(application.email,"ULTIMA Premium-Antrag","Dein Antrag wurde derzeit nicht freigegeben. Bei Fragen antworte bitte auf diese E-Mail.")
        audit("admin","premium.application_rejected",None,str(application.id))
        return redirect(url_for("admin_premium"))
    if action != "approve":
        abort(400)
    stripe_key = os.getenv("STRIPE_SECRET_KEY", "").strip()
    if not stripe_key:
        return "Stripe ist noch nicht konfiguriert. Hinterlege STRIPE_SECRET_KEY in Render und versuche es erneut.", 503
    base = os.getenv("ULTIMA_PUBLIC_URL", request.url_root.rstrip("/")).rstrip("/")
    fields = {
        "mode":"subscription",
        "success_url":base+"/premium/success?session_id={CHECKOUT_SESSION_ID}",
        "cancel_url":base+"/premium/cancel",
        "customer_email":application.email,
        "client_reference_id":str(application.id),
        "metadata[application_id]":str(application.id),
        "line_items[0][price_data][currency]":"eur",
        "line_items[0][price_data][unit_amount]":"2999",
        "line_items[0][price_data][recurring][interval]":"month",
        "line_items[0][price_data][product_data][name]":"ULTIMA Premium",
        "line_items[0][price_data][product_data][description]":"Monatliches Premium-Abonnement für die ULTIMA-Webseitenverwaltung",
        "line_items[0][quantity]":"1"
    }
    body = __import__("urllib.parse",fromlist=["urlencode"]).urlencode(fields).encode("utf-8")
    req = Request("https://api.stripe.com/v1/checkout/sessions",data=body,headers={"Authorization":"Bearer "+stripe_key,"Content-Type":"application/x-www-form-urlencoded"},method="POST")
    try:
        with urlopen(req,timeout=20) as response:
            checkout = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        app.logger.warning("Stripe checkout creation failed: %s",type(exc).__name__)
        return "Stripe-Checkout konnte nicht erstellt werden. Bitte Stripe-Konfiguration prüfen.", 502
    application.status="checkout"
    application.approved_at=datetime.now(timezone.utc)
    application.stripe_session_id=checkout.get("id")
    application.checkout_url=checkout.get("url")
    db.session.commit()
    sent=send_premium_email(application.email,"ULTIMA Premium freigegeben – Zahlung abschließen",f"Hallo {application.name},\\n\\nDein Antrag wurde genehmigt. Schließe hier dein ULTIMA-Premium-Abo für 29,99 EUR monatlich ab:\\n{application.checkout_url}\\n\\nApple Pay und Google Pay werden im Stripe-Checkout angezeigt, sofern dein Gerät/Browser und Stripe-Konto dafür berechtigt sind.\\n\\nNach bestätigter Zahlung wird dein Zugang automatisch aktiviert.")
    audit("admin","premium.application_approved",None,str(application.id))
    return render_template_string("<!doctype html><meta charset='utf-8'><body style='background:#080b14;color:white;font:16px system-ui;padding:30px'><h1>Antrag freigegeben</h1><p>Checkout wurde erstellt. E-Mail {{'versendet' if sent else 'nicht versendet – SMTP prüfen'}}.</p><p><a style='color:#8ce4f0' href='{{url}}'>Checkout öffnen</a></p><a href='/admin/premium' style='color:#8ce4f0'>Zurück</a></body>",sent=sent,url=application.checkout_url)

@app.post("/stripe/webhook")
@limiter.limit("120 per minute")
def stripe_webhook():
    secret=os.getenv("STRIPE_WEBHOOK_SECRET","").strip()
    signature=request.headers.get("Stripe-Signature","")
    if not secret or not signature:
        return jsonify(error="Webhook nicht konfiguriert."),400
    try:
        parts=dict(item.split("=",1) for item in signature.split(",") if "=" in item)
        timestamp=parts.get("t","")
        signed=timestamp+"."+request.get_data(as_text=True)
        expected=hmac.new(secret.encode("utf-8"),signed.encode("utf-8"),hashlib.sha256).hexdigest()
        if abs(datetime.now(timezone.utc).timestamp()-int(timestamp))>300 or not secrets.compare_digest(expected,parts.get("v1","")):
            return jsonify(error="Ungültige Webhook-Signatur."),400
        event=request.get_json(force=True)
    except Exception:
        return jsonify(error="Ungültiger Webhook."),400
    if event.get("type")=="checkout.session.completed":
        obj=event.get("data",{}).get("object",{})
        app_id=(obj.get("metadata") or {}).get("application_id") or obj.get("client_reference_id")
        application=db.session.get(PremiumApplication,int(app_id)) if str(app_id or "").isdigit() else None
        if application and obj.get("payment_status")=="paid" and obj.get("mode")=="subscription":
            application.status="active"
            application.stripe_subscription_id=obj.get("subscription")
            application.paid_at=datetime.now(timezone.utc)
            db.session.commit()
            send_premium_email(application.email,"ULTIMA Premium ist freigeschaltet",f"Hallo {application.name},\\n\\ndeine Zahlung wurde bestätigt. Dein ULTIMA-Premiumzugang ist jetzt aktiviert. Anmeldung: {os.getenv('ULTIMA_PUBLIC_URL',request.url_root).rstrip('/')}/admin/login")
            audit("stripe-webhook","premium.subscription_activated",None,str(application.id))
    return jsonify(received=True)

@app.get("/premium/success")
def premium_success():
    return "<!doctype html><meta charset='utf-8'><body style='font:16px system-ui;background:#080b14;color:white;padding:30px'><h1>Zahlung wird bestätigt</h1><p>Dein Zugang wird nach der verifizierten Stripe-Bestätigung automatisch freigeschaltet. Du erhältst eine E-Mail.</p></body>"

@app.get("/premium/cancel")
def premium_cancel():
    return "<!doctype html><meta charset='utf-8'><body style='font:16px system-ui;background:#080b14;color:white;padding:30px'><h1>Checkout abgebrochen</h1><p>Es wurde keine Zahlung bestätigt.</p></body>"

@app.get("/admin/wallets")
@admin_required
def admin_wallets():
    # Only the address already configured for ULTIMA is pre-registered.
    known_address = BTC_ADDRESS or "bc1q4q7lujkr8mcv9e7suet524uxjfwlaxm7aelq5y"
    if re.fullmatch(r"bc1[ac-hj-np-z02-9]{39,59}", known_address):
        existing = ManagedWallet.query.filter_by(network="Bitcoin", address=known_address).first()
        if not existing:
            db.session.add(ManagedWallet(label="ULTIMA Bitcoin Empfangsadresse", network="Bitcoin", address=known_address, purpose="Empfang / Spenden / manuelle TXID-Prüfung", owner_scope="ULTIMA Owner"))
            db.session.commit()
    wallets = ManagedWallet.query.order_by(ManagedWallet.created_at.asc()).all()
    return render_template_string(WALLETS_ADMIN_HTML, wallets=wallets, csrf=session["csrf"], btc_configured=bool(BTC_ADDRESS), owner_email=ADMIN_OWNER_EMAIL)

@app.post("/admin/wallets")
@admin_required
def admin_wallet_add():
    if not admin_csrf_ok():
        abort(400)
    label = request.form.get("label", "").strip()[:120]
    network = request.form.get("network", "").strip()[:40]
    address = request.form.get("address", "").strip()
    purpose = request.form.get("purpose", "Portfolio / read-only").strip()[:240]
    if not label or network not in {"Bitcoin", "Solana", "Ethereum", "Polygon", "Base", "BNB Chain", "Other EVM"} or not address or len(address) > 160:
        abort(400, "Bitte Wallet-Name, unterstütztes Netzwerk und öffentliche Adresse angeben.")
    if network == "Bitcoin" and not re.fullmatch(r"(bc1[ac-hj-np-z02-9]{39,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})", address):
        abort(400, "Ungültiges Bitcoin-Adressformat.")
    if network == "Solana" and not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{32,44}", address):
        abort(400, "Ungültiges Solana-Adressformat.")
    existing = ManagedWallet.query.filter_by(network=network, address=address).first()
    if existing:
        abort(409, "Diese Wallet-Adresse ist bereits eingetragen.")
    db.session.add(ManagedWallet(label=label, network=network, address=address, purpose=purpose or "Portfolio / read-only", owner_scope="ULTIMA Owner"))
    db.session.commit()
    audit("admin:" + session.get("admin_email", ""), "wallet.register", network, label)
    return redirect(url_for("admin_wallets"))

@app.post("/admin/wallets/<int:wallet_id>/delete")
@admin_required
def admin_wallet_delete(wallet_id):
    if not admin_csrf_ok():
        abort(400)
    wallet = db.session.get(ManagedWallet, wallet_id)
    if not wallet:
        abort(404)
    # Keep the configured ULTIMA receive address in the registry.
    if wallet.address == (BTC_ADDRESS or "bc1q4q7lujkr8mcv9e7suet524uxjfwlaxm7aelq5y"):
        abort(400, "Die zentrale ULTIMA-Empfangsadresse kann hier nicht entfernt werden.")
    db.session.delete(wallet)
    db.session.commit()
    audit("admin:" + session.get("admin_email", ""), "wallet.remove", wallet.network, wallet.label)
    return redirect(url_for("admin_wallets"))

@app.get("/admin/business-studio")
@admin_required
def admin_business_studio():
    sites = Site.query.order_by(Site.name.asc()).all()
    projects = WebsiteProject.query.order_by(WebsiteProject.updated_at.desc()).all()
    users = GlobalUser.query.count()
    return render_template_string(BUSINESS_STUDIO_HTML, sites=sites, projects=projects, users=users, csrf=session["csrf"], owner_email=ADMIN_OWNER_EMAIL)

@app.get("/admin")
@admin_required
def admin_home():
    sites = Site.query.order_by(Site.name).all()
    site_data = []
    for site in sites:
        site_data.append({"site": site, "count": Member.query.filter_by(site_id=site.id).count(), "admins": Member.query.filter_by(site_id=site.id, role="site_admin").count(), "orders": StoreOrder.query.filter_by(site_id=site.id).count()})
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    pending_payments = CryptoPayment.query.filter_by(status="pending").order_by(CryptoPayment.created_at.asc()).limit(100).all()
    recent_orders = StoreOrder.query.order_by(StoreOrder.created_at.desc()).limit(100).all()
    invite_codes = RegistrationCode.query.order_by(RegistrationCode.created_at.desc()).limit(100).all()
    return render_template_string(ADMIN_HTML, sites=site_data, logs=logs, csrf=session["csrf"], total=Member.query.count(), payments=pending_payments, wallet=BTC_ADDRESS, orders=recent_orders, order_total=StoreOrder.query.count(), invite_codes=invite_codes, now=datetime.now(timezone.utc), owner_email=ADMIN_OWNER_EMAIL, admin_accounts=Admin.query.count())


@app.post("/admin/bots/run/<bot_id>")
@admin_required
def admin_bot_run(bot_id):
    if not admin_csrf_ok():
        abort(400)
    sites = Site.query.order_by(Site.slug).all()
    result = {}
    if bot_id == "site-health":
        def check(site):
            host = urlparse(site.origin)
            if host.scheme != "https" or not host.hostname or not host.hostname.endswith(".onrender.com"):
                return {"site": site.slug, "status": "skipped"}
            path = "/health" if site.slug == "ultima-membership-api" else "/api/health"
            try:
                req = Request(site.origin.rstrip("/") + path, headers={"User-Agent": "ULTIMA-SiteHealthBot/1.0"})
                with urlopen(req, timeout=4) as response:
                    return {"site": site.slug, "status": "ok" if response.status < 400 else "warning", "http": response.status}
            except Exception as exc:
                return {"site": site.slug, "status": "warning", "error": type(exc).__name__}
        rows = []
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = [pool.submit(check, site) for site in sites if site.is_active]
            for future in as_completed(futures):
                rows.append(future.result())
        result = {"checked": len(rows), "healthy": sum(x["status"] == "ok" for x in rows), "warnings": [x for x in rows if x["status"] != "ok"]}
    elif bot_id == "member-guard":
        findings = []
        for site in sites:
            members = Member.query.filter_by(site_id=site.id).all()
            bad = [m.id for m in members if "@" not in (m.email or "") or "." not in (m.email or "").split("@")[-1]]
            inactive = sum(1 for m in members if m.status != "active")
            if bad or inactive:
                findings.append({"site": site.slug, "invalid_email_member_ids": bad[:20], "inactive_members": inactive})
        result = {"sites_scanned": len(sites), "findings": findings}
    elif bot_id == "order-monitor":
        details = []
        for site in sites:
            latest = StoreOrder.query.filter_by(site_id=site.id).order_by(StoreOrder.created_at.desc()).first()
            details.append({"site": site.slug, "orders": StoreOrder.query.filter_by(site_id=site.id).count(), "last_order": latest.created_at.isoformat() if latest else None, "site_token_issued": bool(site.webhook_token_hash)})
        result = {"sites": details, "total_orders": sum(x["orders"] for x in details)}
    elif bot_id == "audit-watch":
        since = datetime.now(timezone.utc) - timedelta(hours=24)
        rows = AuditLog.query.filter(AuditLog.created_at >= since).order_by(AuditLog.created_at.desc()).limit(300).all()
        flagged = [x for x in rows if any(term in x.action.lower() for term in ("failed", "denied", "reject", "disabled"))]
        result = {"events_last_24h": len(rows), "flagged": [{"actor": x.actor, "action": x.action, "site": x.site_slug} for x in flagged[:50]]}
    else:
        abort(404)
    db.session.add(AuditLog(actor="bot:" + bot_id, action="bot.run", target=json.dumps(result, ensure_ascii=False, default=str)[:4000], ip=(request.remote_addr or "")[:64]))
    db.session.commit()
    return render_template_string("<!doctype html><meta charset='utf-8'><meta name='viewport' content='width=device-width'><body style='background:#080b14;color:#edf1ff;font:16px system-ui;padding:24px'><h1>ULTIMA Bot-Bericht</h1><p><a href='/admin'>Control Center</a></p><pre style='white-space:pre-wrap;overflow-wrap:anywhere'>{{ report }}</pre></body>", report=json.dumps(result, ensure_ascii=False, indent=2, default=str))

@app.post("/admin/sites")
@admin_required
def admin_create_site():
    if not admin_csrf_ok():
        abort(400)
    name = request.form.get("name", "").strip()[:120]
    slug = request.form.get("slug", "").strip().lower()
    origin = request.form.get("origin", "").strip().rstrip("/")
    if not name or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,62}", slug) or not origin.startswith("https://"):
        abort(400)
    if Site.query.filter_by(slug=slug).first():
        abort(409)
    db.session.add(Site(name=name, slug=slug, origin=origin))
    db.session.commit()
    audit("admin", "site.created", slug, origin)
    return redirect(url_for("admin_home"))

@app.get("/admin/site/<slug>")
@admin_required
def admin_site(slug):
    site = Site.query.filter_by(slug=slug).first_or_404()
    members = Member.query.filter_by(site_id=site.id).order_by(Member.created_at.desc()).limit(500).all()
    orders = StoreOrder.query.filter_by(site_id=site.id).order_by(StoreOrder.created_at.desc()).limit(500).all()
    payments = CryptoPayment.query.filter_by(site_id=site.id).order_by(CryptoPayment.created_at.desc()).limit(300).all()
    ledger = CreditLedger.query.filter_by(site_id=site.id).order_by(CreditLedger.created_at.desc()).limit(300).all()
    widget_snippet = (
        '<script src="https://ultima-membership-api.onrender.com/membership-widget.js"></script>\n'
        '<script>window.addEventListener("DOMContentLoaded", function(){window.UltimaMembership.init({siteSlug: ' + json.dumps(site.slug) + ', brand: ' + json.dumps(site.name, ensure_ascii=False) + '});});</script>'
    )
    return render_template_string(SITE_HTML, site=site, members=members, orders=orders, payments=payments, ledger=ledger, csrf=session["csrf"], widget_snippet=widget_snippet)

@app.post("/admin/site/<slug>/member/<int:member_id>")
@admin_required
def admin_member_action(slug, member_id):
    if not admin_csrf_ok():
        abort(400)
    site = Site.query.filter_by(slug=slug).first_or_404()
    member = Member.query.filter_by(id=member_id, site_id=site.id).first_or_404()
    action = request.form.get("action")
    if action == "disable":
        member.status = "disabled"
        member.token_version += 1
    elif action == "enable":
        member.status = "active"
    elif action == "promote":
        member.role = "site_admin"
    elif action == "demote":
        member.role = "member"
    else:
        abort(400)
    db.session.commit()
    audit("admin", "member." + action, slug, str(member.id))
    return redirect(url_for("admin_site", slug=slug))


@app.get("/api/<slug>/admin/members")
def local_admin_members(slug):
    site, actor = current_member(slug)
    if not site or not actor or actor.role not in ("site_admin", "superadmin"):
        return jsonify(error="Keine Berechtigung."), 403
    rows = Member.query.filter_by(site_id=site.id).order_by(Member.created_at.desc()).limit(500).all()
    return jsonify(members=[{"id": m.id, "username": m.username, "email": m.email, "role": m.role, "status": m.status, "created_at": m.created_at.isoformat()} for m in rows])

@app.patch("/api/<slug>/admin/members/<int:member_id>")
def local_admin_member_action(slug, member_id):
    site, actor = current_member(slug)
    if not site or not actor or actor.role not in ("site_admin", "superadmin"):
        return jsonify(error="Keine Berechtigung."), 403
    target = Member.query.filter_by(id=member_id, site_id=site.id).first()
    if not target:
        return jsonify(error="Mitglied nicht gefunden."), 404
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    if action == "approve" and target.status == "pending":
        target.status = "active"
    elif action == "disable":
        target.status = "disabled"
        target.token_version += 1
    elif action == "enable":
        target.status = "active"
    elif action == "promote" and actor.role == "superadmin":
        target.role = "site_admin"
    elif action == "demote" and actor.role == "superadmin":
        target.role = "member"
    else:
        return jsonify(error="Aktion nicht erlaubt."), 403
    db.session.commit()
    audit("member:" + actor.username, "local.member." + action, site.slug, str(target.id))
    return jsonify(ok=True)

@app.get("/site-admin/<slug>")
def local_site_admin(slug):
    site, member = current_member(slug)
    if not site or not member or member.role not in ("site_admin", "superadmin"):
        return jsonify(error="Keine Berechtigung für diese Webseiten-Administration."), 403
    members = Member.query.filter_by(site_id=site.id).order_by(Member.created_at.desc()).limit(500).all()
    return render_template_string(SITE_READONLY_HTML, site=site, members=members, admin_name=member.username)

@app.get("/admin/api/overview")
@admin_required
def admin_overview():
    sites = Site.query.order_by(Site.name).all()
    return jsonify(sites=[{"slug": s.slug, "name": s.name, "origin": s.origin, "members": Member.query.filter_by(site_id=s.id).count(), "active": s.is_active} for s in sites], total_members=sum(Member.query.filter_by(site_id=s.id).count() for s in sites))

SETUP_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA Setup</title><body style="font:16px system-ui;background:#090d18;color:#fff;max-width:520px;margin:8vh auto;padding:24px"><h1>ULTIMA · Erstadministrator</h1><p>Einmalige sichere Einrichtung. Das Setup-Token wird nicht gespeichert.</p><form id="f"><input id="email" type="email" placeholder="Admin-E-Mail" required style="display:block;width:100%;padding:12px;margin:10px 0"><input id="password" type="password" placeholder="Passwort (mind. 14 Zeichen)" required style="display:block;width:100%;padding:12px;margin:10px 0"><input id="token" type="password" placeholder="Setup-Token" required style="display:block;width:100%;padding:12px;margin:10px 0"><button style="padding:12px 18px">Administrator anlegen</button></form><pre id="out"></pre><script>f.onsubmit=async e=>{e.preventDefault();let r=await fetch('/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email.value,password:password.value,setup_token:token.value})});out.textContent=JSON.stringify(await r.json(),null,2)}</script></body></html>"""
LOGIN_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA Admin Login</title><body style="font:16px system-ui;background:#090d18;color:#fff;max-width:440px;margin:10vh auto;padding:24px"><h1>ULTIMA Control Center</h1><p>Administrator-Anmeldung</p>{% if error %}<p style="color:#ff9c9c">{{error}}</p>{% endif %}<form method="post"><input name="email" type="email" placeholder="E-Mail" required style="display:block;width:100%;padding:12px;margin:10px 0"><input name="password" type="password" placeholder="Passwort" required style="display:block;width:100%;padding:12px;margin:10px 0"><button style="padding:12px 18px">Anmelden</button></form></body></html>"""
WALLETS_ADMIN_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA · Wallet-Verwaltung</title><style>body{margin:0;background:#080b14;color:#edf1ff;font:15px system-ui}main{max-width:1100px;margin:30px auto;padding:0 18px}header{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}a{color:#8ce4f0}.card{background:#11182a;border:1px solid #26304a;border-radius:15px;padding:18px;margin:14px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}input,select,button{padding:11px;border-radius:9px;border:1px solid #36415f;background:#0b1222;color:#fff;margin:4px;max-width:100%}button{cursor:pointer;background:#293b68}.addr{overflow-wrap:anywhere;font:12px ui-monospace,monospace;color:#8ce4f0}.muted{color:#a8b4cd;font-size:12px}.warn{border-color:#78602e;color:#f0d69d}form{margin:0}</style><main><header><div><h1>₿ ULTIMA Wallet-Verwaltung</h1><p class="muted">Zentrale Übersicht öffentlicher Wallet-Adressen · Inhaber: {{owner_email}}</p></div><nav><a href="/admin">← Control Center</a> · <a href="/admin/business-studio">Business Studio →</a></nav></header><section class="card warn"><b>Schlüsselsicherheit:</b> Hier werden ausschließlich öffentliche Empfangs-/Portfolio-Adressen verwaltet. Keine Seed-Phrasen, Private Keys oder Signaturdaten eintragen. Es gibt keine Verwahrung und keine automatische Transaktionsfreigabe. Die zentrale Bitcoin-Adresse ist {{'als Render-Variable konfiguriert' if btc_configured else 'aus dem bekannten Projektkontext vorbefüllt; Render-Variable BTC_RECEIVE_ADDRESS ist noch zu konfigurieren'}}.</section><h2>Registrierte Wallets ({{wallets|length}})</h2><div class="grid">{% for w in wallets %}<article class="card"><b>{{w.label}}</b><p class="muted">{{w.network}} · {{w.purpose}}</p><p class="addr">{{w.address}}</p><p class="muted">{{w.owner_scope}} · hinzugefügt {{w.created_at}}</p>{% if not (w.network == 'Bitcoin' and w.address == 'bc1q4q7lujkr8mcv9e7suet524uxjfwlaxm7aelq5y') %}<form method="post" action="/admin/wallets/{{w.id}}/delete"><input type="hidden" name="csrf" value="{{csrf}}"><button>Eintrag entfernen</button></form>{% endif %}</article>{% else %}<p>Noch keine Wallet eingetragen.</p>{% endfor %}</div><section class="card"><h2>Weitere eigene Wallet hinzufügen</h2><p class="muted">Trage hier nur öffentliche Adressen ein. Nutzer- oder Unternehmens-Wallets werden nicht automatisch aus Apps ausgelesen.</p><form method="post" action="/admin/wallets"><input type="hidden" name="csrf" value="{{csrf}}"><p><input name="label" placeholder="Bezeichnung, z. B. Krypto-Aurora Treasury" required></p><p><select name="network" required><option value="">Netzwerk wählen</option><option>Bitcoin</option><option>Solana</option><option>Ethereum</option><option>Polygon</option><option>Base</option><option>BNB Chain</option><option>Other EVM</option></select><input name="address" placeholder="Öffentliche Wallet-Adresse" required style="width:min(600px,90%)"></p><p><input name="purpose" placeholder="Zweck (optional)" style="width:min(600px,90%)"></p><button>Wallet registrieren</button></form></section><p class="muted">Wallets werden in der ULTIMA-Datenbank gespeichert. Kontostände, Token-Metadaten und Transaktionen benötigen je Netzwerk einen separaten, geprüften Read-only-Provider.</p></main></html>"""

BUSINESS_STUDIO_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA · Business Studio</title><style>body{margin:0;background:radial-gradient(ellipse at 60% -20%,#26395d,transparent 55%),#080b14;color:#edf1ff;font:15px system-ui}main{max-width:1200px;margin:28px auto;padding:0 18px}header{display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}a{color:#8ce4f0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:14px}.card{background:#11182a;border:1px solid #26304a;border-radius:15px;padding:18px;min-width:0}.muted{color:#a8b4cd;font-size:12px}.stat{font-size:28px;font-weight:800}.pill{display:inline-block;padding:4px 8px;border:1px solid #3b5970;border-radius:99px;color:#9fe7e9;font-size:11px}.url{overflow-wrap:anywhere}.section{margin:28px 0}.wallet{background:linear-gradient(120deg,#1a2940,#10212d);border-color:#78653c}</style><main><header><div><h1>✦ ULTIMA Business Studio</h1><p class="muted">Deine eigene Polsia-inspirierte Verwaltungszentrale für Unternehmen, KI-Produkte und Websites.</p></div><nav><a href="/admin">← Control Center</a> · <a href="/admin/wallets">₿ Wallet-Verwaltung →</a></nav></header><div class="grid"><section class="card"><div class="muted">REGISTRIERTE WEBPLATTFORMEN</div><div class="stat">{{sites|length}}</div></section><section class="card"><div class="muted">EIGENE PROJEKT-EINTRÄGE</div><div class="stat">{{projects|length}}</div></section><section class="card"><div class="muted">GLOBALE BENUTZER</div><div class="stat">{{users}}</div></section></div><section class="section"><h2>Unternehmen & Plattformen</h2><p class="muted">Die vorhandenen ULTIMA-Websites werden als Geschäftsbereiche dargestellt. Dies ist ein Service-/Projektportfolio, kein Nachweis einer rechtlich eingetragenen Gesellschaft oder ihrer Eigentumsverhältnisse.</p><div class="grid">{% for s in sites %}<article class="card"><span class="pill">{{'Aktiv' if s.is_active else 'Deaktiviert'}}</span><h3>{{s.name}}</h3><p class="muted">{{s.slug}} · Mitgliedschaft {{'aktiviert' if s.membership_enabled else 'deaktiviert'}}</p><p class="url"><a href="{{s.origin}}" target="_blank" rel="noopener">{{s.origin}}</a></p><a href="/admin/site/{{s.slug}}">Website verwalten →</a></article>{% else %}<p>Keine Websites in der Datenbank registriert.</p>{% endfor %}</div></section><section class="section"><h2>Ideen, Produkte & neue Unternehmensprojekte</h2><div class="grid">{% for p in projects %}<article class="card"><span class="pill">{{p.status}} · {{p.category}}</span><h3>{{p.name}}</h3><p>{{p.description}}</p><p class="url"><a href="{{p.url}}" target="_blank" rel="noopener">{{p.url}}</a></p><p class="muted">Eigentümer-Konto: {{p.owner.email}}</p></article>{% else %}<p class="muted">Noch keine zusätzlichen Nutzer-Projekte registriert.</p>{% endfor %}</div><p><a href="/admin/website-projects">Projektfreigaben und Veröffentlichungen verwalten →</a></p></section><section class="card wallet"><h2>Wallets & Treasury</h2><p>Die zentrale Wallet-Verwaltung bündelt bekannte Empfangsadressen und weitere öffentliche Unternehmens-Wallets.</p><a href="/admin/wallets">Wallet Hub öffnen →</a></section><section class="card"><h2>Operative Steuerung</h2><p>Mitglieder, Premium, Bestellungen, Rechnungen, Freigaben, Site-Health und Audit-Protokolle bleiben über das ULTIMA Control Center erreichbar.</p><a href="/admin">Zum Control Center →</a></section><p class="muted">Polsia-inspiriertes eigenes Business Studio. Keine Verbindung zu Polsia Inc. und kein vollständiger Klon eines fremden Dienstes.</p></main></html>"""

ADMIN_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA Control Center</title><style>body{margin:0;background:#080b14;color:#edf1ff;font:15px system-ui}header{padding:22px 5vw;border-bottom:1px solid #26304a;display:flex;justify-content:space-between}main{max-width:1100px;margin:30px auto;padding:0 18px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}.card{background:#11182a;border:1px solid #26304a;border-radius:16px;padding:18px}input,button{padding:11px;border-radius:9px;border:1px solid #36415f;background:#0b1222;color:#fff;margin:4px}button{cursor:pointer;background:#293b68}a{color:#8ce4f0}small{color:#a8b4cd}.stat{font-size:28px;font-weight:800}</style><header><b>✦ ULTIMA CONTROL CENTER</b><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{csrf}}"><button>Abmelden</button></form></header><main><h1>Plattformverwaltung</h1><p><a href="/admin/business-studio">✦ ULTIMA Business Studio · Polsia-inspirierte Unternehmenszentrale →</a> · <a href="/admin/wallets">₿ Wallet-Verwaltung →</a> · <a href="/admin/website-projects">🌐 Öffentliche Website-Projekte verwalten →</a> · <a href="/portal">Globales Konto & Website-Studio öffnen →</a></p><p><a href="/admin/credits">Legacy-Credit-Review →</a> · <a href="/admin/premium">✦ Network Premium · Mitgliedschaften, Testphasen und Bitcoin-Rechnungen verwalten →</a></p><p><a href="/cyber-shield">◈ Cyber Shield · Sicherheitszentrale öffnen →</a></p><p>Zentrale Inhaberkontrolle · einzelne Webseiten mit getrennten Integrationsschlüsseln · lokale Rollen ohne Superadmin-Rechte</p><div class="grid"><section class="card"><small>ALLEINIGER SUPERADMIN / INHABER</small><h2>{{owner_email}}</h2><p><b>ULTIMA Owner</b> · Vollzugriff auf die zentrale Verwaltung</p><small>Weitere E-Mail-Adressen werden beim zentralen Admin-Login abgewiesen. Sitzungs-Timeout: 30 Minuten Inaktivität, maximal 8 Stunden.</small></section><section class="card"><small>ZENTRALE ADMIN-KONTEN</small><div class="stat">{{admin_accounts}}</div><p><small>Erlaubte Inhaberadresse: {{owner_email}} · andere Konten werden durch die Zugriffskontrolle blockiert.</small></p></section><section class="card"><h3>Commerce Hub · Shopify-ähnlich</h3><p>Bestellungen, Rechnungen, Zahlungs- und Versandstatus sowie Shop-Webhooks zentral verwalten.</p><a href="#orders">Zu Bestellungen ↓</a></section><section class="card"><h3>Business Studio · Polsia-inspiriert</h3><p>Unternehmensportfolio, Websites, KI-Projekte und operative Verwaltung an einem Ort.</p><a href="/admin/business-studio">Business Studio öffnen →</a></section><section class="card"><h3>Integrierte Automations-Bots</h3><p>Site Health · Member Guard · Order Monitor · Audit Watch. Prüfungen sind lesend; Zahlungen bleiben manuell.</p><form method="post" action="/admin/bots/run/site-health"><input type="hidden" name="csrf" value="{{csrf}}"><button>Site Health Bot starten</button></form><form method="post" action="/admin/bots/run/member-guard"><input type="hidden" name="csrf" value="{{csrf}}"><button>Member Guard starten</button></form><form method="post" action="/admin/bots/run/order-monitor"><input type="hidden" name="csrf" value="{{csrf}}"><button>Order Monitor starten</button></form><form method="post" action="/admin/bots/run/audit-watch"><input type="hidden" name="csrf" value="{{csrf}}"><button>Audit Watch starten</button></form><a href="/admin/credits">Credit-Review öffnen →</a></section></div><div class="grid"><section class="card"><small>MITGLIEDER GESAMT</small><div class="stat">{{total}}</div></section><section class="card"><small>PLATTFORMEN</small><div class="stat">{{sites|length}}</div></section></div><h2>Einmalige Registrierungscodes</h2><section class="card"><p>Jeder neue Account benötigt einen individuellen Code. Er gilt nur für eine Webseite, einmalig und sieben Tage.</p><form method="post" action="/admin/invites/create"><input type="hidden" name="csrf" value="{{csrf}}"><select name="site_slug" required>{% for item in sites %}{% if item.site.is_active and item.site.membership_enabled %}<option value="{{item.site.slug}}">{{item.site.name}}</option>{% endif %}{% endfor %}</select><button>Einmaligen Code erzeugen</button></form><table width="100%" cellpadding="8"><tr><th>Webseite</th><th>Erstellt</th><th>Gültig bis</th><th>Status</th><th>Aktion</th></tr>{% for c in invite_codes %}<tr><td>{{c.site.name}}</td><td>{{c.created_at}}</td><td>{{c.expires_at}}</td><td>{% if c.used_at %}Verwendet{% elif c.revoked_at %}Widerrufen{% elif c.expires_at <= now %}Abgelaufen{% else %}Aktiv{% endif %}</td><td>{% if not c.used_at and not c.revoked_at and c.expires_at > now %}<form method="post" action="/admin/invites/{{c.id}}/revoke"><input type="hidden" name="csrf" value="{{csrf}}"><button>Widerrufen</button></form>{% endif %}</td></tr>{% else %}<tr><td colspan="5">Noch keine Codes erzeugt.</td></tr>{% endfor %}</table></section><h2 id="sites">Webseiten & Geschäftsprojekte integrieren</h2><form method="post" action="/admin/sites" class="card"><input type="hidden" name="csrf" value="{{csrf}}"><input name="name" placeholder="Webseitenname" required><input name="slug" placeholder="slug-zum-beispiel" required><input name="origin" placeholder="https://deine-seite.onrender.com" required><button>Webseite hinzufügen</button></form><h2 id="orders">Bestellungen & Rechnungen · {{order_total}} Bestellungen</h2><section class="card"><table width="100%" cellpadding="8"><tr><th>Webseite</th><th>Bestellung</th><th>Kunde</th><th>Betrag</th><th>Zahlung</th><th>Versand</th><th>Rechnung</th></tr>{% for o in orders %}<tr><td>{{o.site.name}}</td><td>{{o.order_number}}</td><td>{{o.customer_name}}<br><small>{{o.customer_email}}</small></td><td>{{o.total_amount}} {{o.currency}}</td><td>{{o.payment_status}}</td><td>{{o.fulfillment_status}}</td><td><a href="/admin/order/{{o.id}}/invoice">Rechnung öffnen</a></td></tr>{% endfor %}</table></section><h2>Mitgliedschaften pro Webseite</h2><div class="grid">{% for item in sites %}<section class="card"><h3>{{item.site.name}}</h3><small>{{item.site.origin}}</small><div class="stat">{{item.count}}</div><p><a href="/admin/site/{{item.site.slug}}">Mitglieder verwalten →</a></p><small>{{item.admins}} lokale Administratoren · {{item.orders}} Bestellungen · {{'aktiv' if item.site.is_active else 'deaktiviert'}}</small></section>{% endfor %}</div><h2>Bitcoin-Zahlungen zur Prüfung</h2><section class="card"><p>Empfangsadresse: <b>{{wallet or "Noch nicht konfiguriert"}}</b> · Bitcoin mainnet</p>{% for p in payments %}<p>{{p.created_at}} · {{p.site.name}} · Mitglied #{{p.member_id}} · ${{p.amount_usd}} / {{p.credits}} Credits · TXID: <code>{{p.txid}}</code><form method="post" action="/admin/payment/{{p.id}}/approve" style="display:inline"><input type="hidden" name="csrf" value="{{csrf}}"><button>Zahlung bestätigen & Credits gutschreiben</button></form><form method="post" action="/admin/payment/{{p.id}}/reject" style="display:inline"><input type="hidden" name="csrf" value="{{csrf}}"><button>Ablehnen</button></form></p>{% else %}<small>Keine offenen Zahlungen.</small>{% endfor %}</section><h2>Letzte Verwaltungsaktionen</h2><section class="card">{% for log in logs %}<p><small>{{log.created_at}} · {{log.actor}} · {{log.action}} · {{log.site_slug or 'global'}}</small></p>{% else %}<small>Noch keine Aktionen.</small>{% endfor %}</section></main></html>"""
TOKEN_ONCE_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA · Token einmalig anzeigen</title><body style="background:#080b14;color:#edf1ff;font:16px system-ui;max-width:760px;margin:8vh auto;padding:24px"><h1>Neuer Integrationstoken</h1><p>Website: {{site.name}}</p><p><b>Dieser Token wird nur jetzt angezeigt.</b> Kopiere ihn in die Secret-/Environment-Einstellungen der angebundenen Website. Er wird nicht erneut gespeichert oder angezeigt.</p><pre id="token" style="white-space:pre-wrap;overflow-wrap:anywhere;background:#11182a;padding:18px;border-radius:12px">{{token}}</pre><button onclick="navigator.clipboard.writeText(document.getElementById('token').textContent)">Token kopieren</button> <a href="/admin/site/{{site.slug}}" style="color:#8ce4f0">Zurück zur Website</a></body></html>"""
SITE_HTML = """<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#171717">
<title>{{site.name}} · ULTIMA Control Center</title>
<style>
:root{color-scheme:dark;--bg:#212121;--sidebar:#171717;--panel:#2b2b2b;--panel2:#303030;--line:#414141;--text:#f5f5f5;--muted:#a1a1aa;--green:#10a37f;--green2:#0d8b6c;--red:#b85c5c;--radius:16px}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:28px}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 Inter,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
a{color:#8bd9c3;text-decoration:none}a:hover{color:#b5f0df}
.shell{min-height:100vh;display:grid;grid-template-columns:248px minmax(0,1fr)}
.sidebar{height:100vh;position:sticky;top:0;background:var(--sidebar);border-right:1px solid #303030;padding:22px 14px;display:flex;flex-direction:column;gap:22px}
.brand{display:flex;align-items:center;gap:11px;padding:4px 8px 20px;border-bottom:1px solid #303030}.mark{width:35px;height:35px;border-radius:12px;background:var(--green);display:grid;place-items:center;font-weight:800;font-size:17px}.brand b{font-size:15px;letter-spacing:.04em}.brand small{display:block;color:var(--muted);font-size:11px}
.nav-title{padding:0 10px;color:#777;font-size:10px;font-weight:700;letter-spacing:.13em;text-transform:uppercase}.nav{display:grid;gap:5px}.nav a{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:10px;color:#c8c8c8;transition:.15s}.nav a:hover,.nav a.active{background:#2b2b2b;color:#fff}.nav-icon{width:20px;text-align:center;color:#aaa;font-size:16px}.side-foot{margin-top:auto;border-top:1px solid #303030;padding:15px 9px;color:var(--muted);font-size:12px}
.main{width:100%;max-width:1500px;min-width:0;margin:0 auto;padding:30px clamp(18px,4vw,58px) 80px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin-bottom:32px}.crumb{font-size:13px;color:var(--muted)}.crumb b{color:#eee}.live-pill{display:inline-flex;align-items:center;gap:8px;border:1px solid #414141;background:#292929;padding:7px 12px;border-radius:999px;font-size:12px;color:#ddd}.live-dot{width:7px;height:7px;border-radius:50%;background:#20c997;box-shadow:0 0 10px #20c99766}
h1{font-size:clamp(27px,3vw,36px);line-height:1.15;letter-spacing:-.04em;margin:0 0 8px;font-weight:680}h2{font-size:19px;letter-spacing:-.025em;margin:0 0 5px;font-weight:630}h3{font-size:14px;margin:0 0 5px}.muted,.section-head p,.lead{color:var(--muted)}.lead{margin:0 0 26px;font-size:14px}.section-head p{font-size:13px;margin:4px 0 0}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:24px 0 34px}.stat-card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:17px 18px}.stat-label{font-size:12px;color:var(--muted)}.stat-value{font-size:26px;font-weight:650;letter-spacing:-.04em;margin-top:5px}.stat-note{font-size:11px;color:#888;margin-top:2px}
.section{margin:34px 0}.section-head{display:flex;align-items:flex-end;justify-content:space-between;gap:14px;margin-bottom:14px}.card{background:var(--panel);border:1px solid var(--line);border-radius:var(--radius);padding:22px;margin:12px 0;box-shadow:0 8px 24px #00000012}.card-top{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}
.grid-two{display:grid;grid-template-columns:1fr 1fr;gap:15px}.field{display:grid;gap:7px}.field label,.check-label{font-size:13px;color:#d4d4d4;font-weight:550}
input:not([type=checkbox]),select,textarea{width:100%;min-width:0;background:#212121;border:1px solid #555;color:#f4f4f4;border-radius:10px;padding:11px 12px;font:inherit;outline:none}input:focus,select:focus,textarea:focus{border-color:#888;box-shadow:0 0 0 2px #fff1}.checks{display:flex;gap:20px;flex-wrap:wrap;margin:18px 0}.check-label{display:flex;align-items:center;gap:9px}.check-label input{width:16px;height:16px;accent-color:var(--green)}
button,.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:10px 15px;border:1px solid transparent;border-radius:10px;background:var(--green);color:#fff;font:600 13px Inter,-apple-system,sans-serif;cursor:pointer;text-decoration:none;transition:.15s}button:hover,.btn:hover{background:var(--green2)}button.secondary{background:#383838;border-color:#555;color:#eee}button.secondary:hover{background:#474747}button.danger{background:#3b2525;border-color:#704040;color:#ffbaba}button.danger:hover{background:#523030}
.status{display:inline-flex;align-items:center;gap:6px;padding:5px 10px;border-radius:999px;background:#173c32;color:#91e5c9;font-size:11px;font-weight:650}.status.off{background:#3a2929;color:#f1aaaa}.codebox{width:100%;min-height:116px;resize:vertical;font:12px/1.65 ui-monospace,SFMono-Regular,monospace!important;background:#1c1c1c!important;border:1px solid #4a4a4a!important;border-radius:11px;padding:14px!important;color:#d8e5df!important}
.actions{display:flex;gap:9px;flex-wrap:wrap;margin:13px 0}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:12px}table{width:100%;border-collapse:collapse;min-width:720px;background:#262626}th,td{padding:12px 14px;text-align:left;border-bottom:1px solid #414141;vertical-align:middle}th{font-size:10px;text-transform:uppercase;letter-spacing:.08em;color:#aaa;background:#303030;white-space:nowrap}td{font-size:13px;color:#e3e3e3}tr:last-child td{border-bottom:0}tbody tr:hover{background:#303030}td form{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin:0}td select{width:auto;max-width:130px;padding:7px;font-size:12px}td button{padding:7px 10px;font-size:11px}.mono{font:12px ui-monospace,monospace;overflow-wrap:anywhere}.empty{padding:25px;text-align:center;color:var(--muted)}.hint{font-size:12px;color:var(--muted);margin-top:12px}
@media(max-width:950px){.shell{grid-template-columns:1fr}.sidebar{position:relative;height:auto;padding:12px 16px;gap:12px}.brand{padding-bottom:10px}.nav{display:flex;overflow:auto}.nav-title,.side-foot{display:none}.nav a{white-space:nowrap;padding:8px 10px}.main{padding:24px 16px 56px}}
@media(max-width:650px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}.grid-two{grid-template-columns:1fr}.card{padding:16px}.topbar{align-items:flex-start}.section-head{align-items:flex-start;flex-direction:column}}
:focus-visible{outline:2px solid #78cdb5;outline-offset:3px}
</style>
</head>
<body>
<div class="shell">
<aside class="sidebar">
  <div class="brand"><div class="mark">U</div><div><b>ULTIMA</b><small>Control Center</small></div></div>
  <div class="nav-title">Verwaltung</div>
  <nav class="nav">
    <a href="/admin"><span class="nav-icon">⌂</span>Übersicht</a>
    <a class="active" href="#overview"><span class="nav-icon">▦</span>Dashboard</a>
    <a href="#settings"><span class="nav-icon">⚙</span>Website-Einstellungen</a>
    <a href="#widget"><span class="nav-icon">⌘</span>Integration</a>
    <a href="#orders"><span class="nav-icon">▤</span>Bestellungen</a>
    <a href="#credits"><span class="nav-icon">◈</span>Credits & Zahlungen</a>
    <a href="#members"><span class="nav-icon">♙</span>Mitglieder</a>
  </nav>
  <div class="side-foot">ULTIMA NETWORK<br><span>Getrennte Konten · Zentrale Verwaltung</span></div>
</aside>
<main class="main">
  <div class="topbar"><div class="crumb">Control Center <span> / </span> <b>{{site.name}}</b></div><div class="actions"><a class="btn" href="/portal">Eigene Websites verwalten ↗</a><a class="btn secondary" href="https://ultima-central-bt56.onrender.com" target="_blank" rel="noopener noreferrer">ULTIMA Central ↗</a><a class="btn secondary" href="https://astralis-app-center.onrender.com" target="_blank" rel="noopener noreferrer">ASTRALIS App Center ↗</a><span class="live-pill"><span class="live-dot"></span>Verwaltungsbereich</span></div></div>
  <header id="overview"><h1>{{site.name}}</h1><p class="lead">Dein zentraler Arbeitsbereich für Mitglieder, Integrationen, Bestellungen und Credits.</p></header>
  <section class="stats">
    <div class="stat-card"><div class="stat-label">Mitglieder</div><div class="stat-value">{{members|length}}</div><div class="stat-note">Konten dieser Website</div></div>
    <div class="stat-card"><div class="stat-label">Bestellungen</div><div class="stat-value">{{orders|length}}</div><div class="stat-note">Erfasste Bestellungen</div></div>
    <div class="stat-card"><div class="stat-label">Credit-Käufe</div><div class="stat-value">{{payments|length}}</div><div class="stat-note">Zahlungsvorgänge</div></div>
    <div class="stat-card"><div class="stat-label">Credit-Buchungen</div><div class="stat-value">{{ledger|length}}</div><div class="stat-note">Kontobewegungen</div></div>
  </section>
  <section class="section" id="settings">
    <div class="section-head"><div><h2>Website-Einstellungen</h2><p>Grunddaten und Funktionen dieser Plattform konfigurieren.</p></div><span class="status {{'off' if not site.is_active else ''}}">{{"Aktiv" if site.is_active else "Deaktiviert"}}</span></div>
    <div class="card">
      <form method="post" action="/admin/site/{{site.slug}}/settings">
        <input type="hidden" name="csrf" value="{{csrf}}">
        <div class="grid-two">
          <div class="field"><label for="site-name">Website-Name</label><input id="site-name" name="name" value="{{site.name}}" required></div>
          <div class="field"><label for="site-origin">Website-URL</label><input id="site-origin" name="origin" type="url" value="{{site.origin}}" required></div>
        </div>
        <div class="checks"><label class="check-label"><input type="checkbox" name="is_active" {% if site.is_active %}checked{% endif %}> Website aktiv</label><label class="check-label"><input type="checkbox" name="membership_enabled" {% if site.membership_enabled %}checked{% endif %}> Mitglieder und Credits aktiv</label></div>
        <button type="submit">Änderungen speichern <span>→</span></button>
      </form>
    </div>
  </section>
  <section class="section" id="widget">
    <div class="section-head"><div><h2>Mitglieder-Widget & API</h2><p>Verbinde diese Website mit dem ULTIMA-Mitgliedersystem.</p></div></div>
    <div class="card">
      <div class="card-top"><strong>Website-Integration</strong><span class="status {{'off' if not site.webhook_token_hash else ''}}">Integrationsschlüssel {{'aktiv' if site.webhook_token_hash else 'nicht vorhanden'}}</span></div>
      <p class="muted">Füge diesen Code im gemeinsamen Website-Footer direkt vor <code>&lt;/body&gt;</code> ein. Mitgliederkonten bleiben pro Website getrennt.</p>
      <textarea class="codebox" readonly rows="5">{{widget_snippet}}</textarea>
      <div class="actions">
        <form method="post" action="/admin/site/{{site.slug}}/integration-token"><input type="hidden" name="csrf" value="{{csrf}}"><button type="submit">{% if site.webhook_token_hash %}Token erneuern{% else %}Token erzeugen{% endif %}</button></form>
        {% if site.webhook_token_hash %}<form method="post" action="/admin/site/{{site.slug}}/integration-token/revoke" onsubmit="return confirm('Integrationstoken wirklich widerrufen? Verbundene Integrationen funktionieren danach erst mit einem neuen Token.')"><input type="hidden" name="csrf" value="{{csrf}}"><button class="danger" type="submit">Token widerrufen</button></form>{% endif %}
      </div>
      <p class="hint">Beim Erneuern wird der bisherige Token sofort ungültig. Den neuen Token sicher in den Environment-Einstellungen der angebundenen Website hinterlegen.</p>
    </div>
  </section>
  <section class="section" id="orders">
    <div class="section-head"><div><h2>Bestellungen & Rechnungen</h2><p>Bestellstatus und Versandinformationen verwalten.</p></div></div>
    <div class="table-wrap"><table><thead><tr><th>Bestellung</th><th>Kunde</th><th>Betrag</th><th>Zahlung</th><th>Versand</th><th>Rechnung</th><th>Bearbeiten</th></tr></thead><tbody>
    {% for o in orders %}<tr><td><strong>{{o.order_number}}</strong></td><td>{{o.customer_name}}<br><small>{{o.customer_email}}</small></td><td>{{o.total_amount}} {{o.currency}}</td><td>{{o.payment_status}}</td><td>{{o.fulfillment_status}}</td><td><a href="/admin/order/{{o.id}}/invoice">Rechnung öffnen ↗</a></td><td><form method="post" action="/admin/order/{{o.id}}/update"><input type="hidden" name="csrf" value="{{csrf}}"><select name="payment_status"><option>{{o.payment_status}}</option><option>pending</option><option>paid</option><option>failed</option><option>refunded</option></select><select name="fulfillment_status"><option>{{o.fulfillment_status}}</option><option>processing</option><option>fulfilled</option><option>shipped</option><option>delivered</option><option>cancelled</option></select><button>Speichern</button></form></td></tr>{% else %}<tr><td class="empty" colspan="7">Noch keine Bestellungen vorhanden.</td></tr>{% endfor %}
    </tbody></table></div>
  </section>
  <section class="section" id="credits">
    <div class="section-head"><div><h2>Credits-Käufe</h2><p>Eingegangene und zugeordnete Aufladungen.</p></div></div>
    <div class="table-wrap"><table><thead><tr><th>Betrag</th><th>Credits</th><th>Transaktions-ID</th><th>Status</th></tr></thead><tbody>
    {% for p in payments %}<tr><td>{{p.amount_usd}} USD</td><td>{{p.credits}}</td><td class="mono">{{p.txid}}</td><td>{{p.status}}</td></tr>{% else %}<tr><td class="empty" colspan="4">Noch keine Credit-Käufe vorhanden.</td></tr>{% endfor %}
    </tbody></table></div>
  </section>
  <section class="section">
    <div class="section-head"><div><h2>Credits & Premium-Freigaben</h2><p>Ausstehende Transaktionen prüfen und bearbeiten.</p></div></div>
    <div class="table-wrap"><table><thead><tr><th>Mitglied</th><th>Betrag</th><th>Credits</th><th>TXID</th><th>Status</th><th>Aktion</th></tr></thead><tbody>
    {% for p in payments %}<tr><td>{{p.member_id}}</td><td>{{p.amount_usd}} USD</td><td>{{p.credits}}</td><td class="mono">{{p.txid}}</td><td>{{p.status}}</td><td>{% if p.status == "pending" %}<form method="post" action="/admin/payment/{{p.id}}/approve"><input type="hidden" name="csrf" value="{{csrf}}"><button>Freigeben</button></form><form method="post" action="/admin/payment/{{p.id}}/reject"><input type="hidden" name="csrf" value="{{csrf}}"><button class="secondary">Ablehnen</button></form>{% else %}—{% endif %}</td></tr>{% else %}<tr><td class="empty" colspan="6">Keine offenen Freigaben.</td></tr>{% endfor %}
    </tbody></table></div>
  </section>
  <section class="section">
    <div class="section-head"><div><h2>Credit-Verlauf</h2><p>Nachvollziehbare Buchungshistorie.</p></div></div>
    <div class="table-wrap"><table><thead><tr><th>Datum</th><th>Mitglied</th><th>Änderung</th><th>Kontostand</th><th>Grund</th></tr></thead><tbody>
    {% for x in ledger %}<tr><td>{{x.created_at}}</td><td>{{x.member_id}}</td><td>{{x.delta}}</td><td>{{x.balance_after}}</td><td>{{x.reason}}</td></tr>{% else %}<tr><td class="empty" colspan="5">Noch keine Buchungen vorhanden.</td></tr>{% endfor %}
    </tbody></table></div>
  </section>
  <section class="section" id="members">
    <div class="section-head"><div><h2>Mitglieder</h2><p>Rollen und Kontozugriff dieser Website verwalten.</p></div></div>
    <div class="table-wrap"><table><thead><tr><th>Benutzer</th><th>E-Mail</th><th>Rolle</th><th>Status</th><th>Aktionen</th></tr></thead><tbody>
    {% for m in members %}<tr><td><strong>{{m.username}}</strong></td><td>{{m.email}}</td><td>{{m.role}}</td><td>{{m.status}}</td><td><form method="post" action="/admin/site/{{site.slug}}/member/{{m.id}}"><input type="hidden" name="csrf" value="{{csrf}}"><button class="secondary" name="action" value="promote">Admin</button><button class="danger" name="action" value="disable">Sperren</button><button class="secondary" name="action" value="enable">Aktivieren</button></form></td></tr>{% else %}<tr><td class="empty" colspan="5">Noch keine Mitglieder registriert.</td></tr>{% endfor %}
    </tbody></table></div>
  </section>
</main>
</div>
</body></html>"""
INVOICE_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><title>Rechnung {{order.invoice_number or order.order_number}}</title><style>body{font:15px Arial;max-width:850px;margin:40px auto;color:#111}header{display:flex;justify-content:space-between;border-bottom:2px solid #222;padding-bottom:20px}table{width:100%;border-collapse:collapse}td,th{padding:10px;border-bottom:1px solid #ddd;text-align:left}.right{text-align:right}@media print{button{display:none}}</style><button onclick="print()">Drucken / als PDF speichern</button><header><div><h1>Rechnung</h1><b>{{site.name}}</b></div><div><b>{{order.invoice_number or order.order_number}}</b><br>{{order.created_at}}</div></header><p>Rechnung an: {{order.customer_name}} · {{order.customer_email}}</p><table><tr><th>Artikel</th><th>Menge</th><th>Einzelpreis</th><th>Gesamt</th></tr>{% for item in order.items_json or [] %}<tr><td>{{item.name}}</td><td>{{item.quantity}}</td><td>{{item.unit_price}}</td><td>{{item.total}}</td></tr>{% endfor %}</table><h2 class="right">Gesamt: {{order.total_amount}} {{order.currency}}</h2><p>Zahlungsstatus: {{order.payment_status}} · Bestellstatus: {{order.fulfillment_status}}</p>{% if order.invoice_url %}<p><a href="{{order.invoice_url}}">Originalrechnung öffnen</a></p>{% endif %}</html>"""
CREDITS_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Credits & Premium · ULTIMA</title><style>body{margin:0;background:#080b14;color:#edf1ff;font:15px system-ui;padding:24px}main{max-width:1200px;margin:auto}.card{background:#11182a;border:1px solid #26304a;border-radius:16px;padding:18px;margin:18px 0}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #293650;text-align:left}button{padding:9px;border:0;border-radius:8px;background:#293b68;color:white}a{color:#8ce4f0}code{overflow-wrap:anywhere}</style><main><h1>Credits- und Premium-Verwaltung</h1><p><a href="/admin">← Zur zentralen Verwaltung</a></p><section class="card"><h2>Alle Aufladungen</h2><table><tr><th>Datum</th><th>Website</th><th>Mitglied</th><th>Betrag</th><th>Credits</th><th>TXID</th><th>Status</th><th>Aktion</th></tr>{% for p in payments %}<tr><td>{{p.created_at}}</td><td>{{p.site.name}}</td><td>{{p.member.email}}</td><td>{{p.amount_usd}} {{p.network}}</td><td>{{p.credits}}</td><td><code>{{p.txid}}</code></td><td>{{p.status}}</td><td>{% if p.status == "pending" %}<form method="post" action="/admin/payment/{{p.id}}/approve"><input type="hidden" name="csrf" value="{{csrf}}"><button>Bestätigen</button></form><form method="post" action="/admin/payment/{{p.id}}/reject"><input type="hidden" name="csrf" value="{{csrf}}"><button>Ablehnen</button></form>{% endif %}</td></tr>{% endfor %}</table></section><section class="card"><h2>Credit-Buchungen</h2><table><tr><th>Datum</th><th>Website</th><th>Mitglied-ID</th><th>Änderung</th><th>Stand</th><th>Grund</th></tr>{% for x in ledger %}<tr><td>{{x.created_at}}</td><td>{{x.site_id}}</td><td>{{x.member_id}}</td><td>{{x.delta}}</td><td>{{x.balance_after}}</td><td>{{x.reason}}</td></tr>{% endfor %}</table></section></main></html>"""
SITE_READONLY_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{site.name}} Admin</title><body style="background:#090d18;color:#fff;font:15px system-ui;padding:24px"><h1>{{site.name}} · Lokale Administration</h1><p>Angemeldet als {{admin_name}}. Diese Ansicht ist auf deine Webseite begrenzt.</p><p>{{members|length}} Mitglieder geladen. Vollständige Aktionen erfolgen über die zentrale Admin-Konsole.</p></body></html>"""

with app.app_context():
    db.create_all()
    site_columns = {col["name"] for col in inspect(db.engine).get_columns("site")}
    if "membership_enabled" not in site_columns:
        db.session.execute(text("ALTER TABLE site ADD COLUMN membership_enabled BOOLEAN NOT NULL DEFAULT TRUE"))
        db.session.commit()
    if "webhook_token_hash" not in site_columns:
        db.session.execute(text("ALTER TABLE site ADD COLUMN webhook_token_hash VARCHAR(64)"))
        db.session.commit()
    if "webhook_token" in site_columns:
        legacy_tokens = db.session.execute(text("SELECT id, webhook_token FROM site WHERE webhook_token IS NOT NULL AND webhook_token != ''")).all()
        for legacy in legacy_tokens:
            db.session.execute(text("UPDATE site SET webhook_token_hash = :digest, webhook_token = NULL WHERE id = :id"), {"digest": hashlib.sha256(legacy.webhook_token.encode("utf-8")).hexdigest(), "id": legacy.id})
        db.session.commit()
    db.session.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_site_webhook_token_hash ON site (webhook_token_hash)"))
    db.session.commit()
    member_columns = {col["name"] for col in inspect(db.engine).get_columns("member")}
    if "credit_balance" not in member_columns:
        db.session.execute(text("ALTER TABLE member ADD COLUMN credit_balance INTEGER NOT NULL DEFAULT 0"))
        db.session.commit()
    if "is_lifetime_premium" not in member_columns:
        db.session.execute(text("ALTER TABLE member ADD COLUMN is_lifetime_premium BOOLEAN NOT NULL DEFAULT FALSE"))
        db.session.commit()
    registry_path = os.path.join(os.path.dirname(__file__), "sites.json")
    if os.path.exists(registry_path):
        with open(registry_path, "r", encoding="utf-8") as registry_file:
            for item in json.load(registry_file):
                registered = Site.query.filter_by(slug=item["slug"]).first()
                if not registered:
                    db.session.add(Site(slug=item["slug"], name=item["name"], origin=item["origin"], membership_enabled=item.get("membership_enabled", True)))
                else:
                    registered.name = item["name"]
                    registered.origin = item["origin"]
                    registered.membership_enabled = item.get("membership_enabled", True)
                    registered.is_active = item.get("is_active", registered.is_active)
        db.session.commit()
    # ULTIMA owner synchronization: the configured owner mailbox is the
    # single master identity across the central portal and all enabled sites.
    if PREMIUM_OWNER_EMAIL:
        Member.query.filter(func.lower(Member.email) == PREMIUM_OWNER_EMAIL).update(
            {"is_lifetime_premium": True}, synchronize_session=False
        )
    if ADMIN_OWNER_EMAIL:
        owner_member_query = Member.query.filter(func.lower(Member.email) == ADMIN_OWNER_EMAIL)
        # Idempotent owner sync: do not invalidate the owner's active sessions
        # merely because Render restarts or deploys this service.
        owner_member_query.update(
            {"role": "superadmin", "status": "active", "is_lifetime_premium": True},
            synchronize_session=False
        )
        global_owner = GlobalUser.query.filter(func.lower(GlobalUser.email) == ADMIN_OWNER_EMAIL).first()
        if global_owner:
            global_owner.role = "owner"
            global_owner.status = "active"
            admin_owner = Admin.query.filter(func.lower(Admin.email) == ADMIN_OWNER_EMAIL).first()
            if not admin_owner:
                # Reuse the same scrypt hash: no new password is generated or exposed.
                admin_owner = Admin(email=global_owner.email, password_hash=global_owner.password_hash, role="superadmin")
                db.session.add(admin_owner)
            else:
                admin_owner.role = "superadmin"
        else:
            admin_owner = Admin.query.filter(func.lower(Admin.email) == ADMIN_OWNER_EMAIL).first()
            if admin_owner:
                admin_owner.role = "superadmin"
        db.session.commit()


class CyberShieldScan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rows_json = db.Column(db.Text, nullable=False)
    scanned_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    created_by = db.Column(db.String(255), nullable=False)

with app.app_context():
    db.create_all()

# ---------------------------------------------------------------------------
# CYBER SHIELD: central security posture dashboard for registered websites.
# This performs safe, read-only HTTPS/header checks; it is not a WAF or
# vulnerability penetration test. New Site records are included automatically.
# ---------------------------------------------------------------------------
@app.after_request
def cyber_shield_response_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.is_secure or app.config.get("SESSION_COOKIE_SECURE"):
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

CYBER_SHIELD_HTML = """<!doctype html>
<html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Cyber Shield · ULTIMA</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#070b14;color:#edf4ff;font:15px Inter,system-ui,sans-serif}
header{padding:22px clamp(18px,5vw,64px);border-bottom:1px solid #263650;display:flex;justify-content:space-between;gap:14px;align-items:center}
main{max-width:1200px;margin:30px auto;padding:0 18px}.muted{color:#9eafc9}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}
.card{background:linear-gradient(145deg,#111d30,#0c1423);border:1px solid #263c59;border-radius:16px;padding:18px;margin:14px 0}
.stat{font-size:30px;font-weight:800}.pill{display:inline-block;padding:5px 9px;border-radius:99px;background:#263650}
.ok{color:#72e3b1}.warn{color:#ffd17b}.bad{color:#ff9292}button,a{color:#dffaff}button{background:#164b62;border:1px solid #2e8297;padding:12px 16px;border-radius:10px;font-weight:700;cursor:pointer}
a{color:#83ddeb}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:11px;border-bottom:1px solid #263650;vertical-align:top}
code{overflow-wrap:anywhere}.top{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
</style><header><b>◈ ULTIMA / CYBER SHIELD</b><a href="/admin">← Control Center</a></header>
<main><div class="top"><div><h1>Cyber Shield</h1><p class="muted">Zentrale Sicherheitsübersicht · Inhaber {{owner}}</p></div>
<form method="post" action="/cyber-shield/scan"><input type="hidden" name="csrf" value="{{csrf}}"><button>Jetzt alle Webseiten prüfen</button></form></div>
<div class="grid"><section class="card"><small class="muted">REGISTRIERTE WEBSITES</small><div class="stat">{{total}}</div></section>
<section class="card"><small class="muted">LETZTER SCAN · ERREICHBAR</small><div class="stat ok">{{healthy}}</div></section>
<section class="card"><small class="muted">WARNUNGEN</small><div class="stat warn">{{warnings}}</div></section>
<section class="card"><small class="muted">PRÜFMODUS</small><div class="stat">READ-ONLY</div></section></div>
<section class="card"><h2>Website-Sicherheitsstatus</h2><p class="muted">Prüft HTTPS-Erreichbarkeit und wichtige HTTP-Sicherheitsheader. Websites werden aus der zentralen Site-Registry geladen – neu hinzugefügte Sites erscheinen automatisch.</p>
<table><thead><tr><th>Website</th><th>HTTPS / HTTP</th><th>Security Header</th><th>Bewertung</th><th>Hinweise</th></tr></thead><tbody>
{% for row in rows %}<tr><td><b>{{row.name}}</b><br><small class="muted">{{row.slug}}</small></td>
<td>{% if row.http %}<span class="ok">{{row.http}}</span>{% else %}<span class="bad">Nicht erreichbar</span>{% endif %}</td>
<td>{{row.present }}/{{row.total }}</td><td>{% if row.score >= 80 %}<span class="ok">{{row.score}} / 100</span>{% elif row.score >= 50 %}<span class="warn">{{row.score}} / 100</span>{% else %}<span class="bad">{{row.score}} / 100</span>{% endif %}</td>
<td>{{row.notes|join(", ") if row.notes else "Keine Header-Warnung aus diesem Check"}}</td></tr>
{% else %}<tr><td colspan="5">Noch kein Scan ausgeführt. Starte oben die Prüfung.</td></tr>{% endfor %}</tbody></table></section>
<section class="card"><h2>Schutzumfang & Grenzen</h2><ul><li>Automatischer Inventar-Abgleich mit allen in ULTIMA registrierten Websites.</li><li>HTTPS-Verbindung, TLS-Zertifikatsprüfung durch den Standard-HTTPS-Client und Security-Header-Check.</li><li>Zentrale Sicherheitsübersicht und Audit-geschützte Scan-Auslösung.</li><li>Diese Prüfung installiert keinen Agenten, keine Firewall und keinen WAF auf den Ziel-Websites.</li><li>Für aktiven Schutz müssen zusätzlich Hosting-/DNS-Firewalls, Rate Limits, sichere Secrets, Updates, Backups und Monitoring je Dienst konfiguriert werden.</li></ul></section>
<p class="muted">Letzter Scan: {{scanned_at or "Noch nicht ausgeführt"}} · Nur registrierte HTTPS-Hosts auf *.onrender.com werden abgefragt.</p></main></html>"""

@app.get("/cyber-shield")
@admin_required
def cyber_shield_home():
    latest = CyberShieldScan.query.order_by(CyberShieldScan.scanned_at.desc()).first()
    rows = json.loads(latest.rows_json) if latest else []
    return render_template_string(CYBER_SHIELD_HTML, owner=ADMIN_OWNER_EMAIL, csrf=session["csrf"],
        total=Site.query.filter_by(is_active=True).count(),
        healthy=sum(1 for x in rows if x.get("http")),
        warnings=sum(1 for x in rows if not x.get("http") or x.get("score", 0) < 80),
        rows=rows, scanned_at=latest.scanned_at.isoformat() if latest else None)

@app.post("/cyber-shield/scan")
@admin_required
@limiter.limit("3 per hour")
def cyber_shield_scan():
    if not admin_csrf_ok():
        abort(400)
    sites = Site.query.filter_by(is_active=True).order_by(Site.name).all()
    required_headers = {
        "Strict-Transport-Security": "HSTS fehlt",
        "Content-Security-Policy": "CSP fehlt",
        "X-Content-Type-Options": "X-Content-Type-Options fehlt",
        "Referrer-Policy": "Referrer-Policy fehlt",
        "Permissions-Policy": "Permissions-Policy fehlt",
    }
    class NoRedirect(__import__("urllib.request", fromlist=["HTTPRedirectHandler"]).HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = __import__("urllib.request", fromlist=["build_opener"]).build_opener(NoRedirect)
    def check(site):
        parsed = urlparse(site.origin)
        if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".onrender.com") or parsed.username or parsed.password:
            return {"name": site.name, "slug": site.slug, "http": None, "present": 0, "total": len(required_headers), "score": 0, "notes": ["Host nicht in der erlaubten HTTPS-Render-Domain"] }
        try:
            req = Request(site.origin.rstrip("/") + "/health", headers={"User-Agent": "ULTIMA-Cyber-Shield/1.0"}, method="GET")
            with opener.open(req, timeout=7) as response:
                headers = response.headers
                status = response.status
            present = sum(1 for key in required_headers if headers.get(key))
            missing = [label for key, label in required_headers.items() if not headers.get(key)]
            score = round((present / len(required_headers)) * 80 + (20 if 200 <= status < 400 else 0))
            return {"name": site.name, "slug": site.slug, "http": status, "present": present, "total": len(required_headers), "score": score, "notes": missing}
        except Exception as exc:
            return {"name": site.name, "slug": site.slug, "http": None, "present": 0, "total": len(required_headers), "score": 0, "notes": ["HTTPS-/Health-Check fehlgeschlagen: " + type(exc).__name__]}
    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = list(pool.map(check, sites))
    db.session.add(CyberShieldScan(rows_json=json.dumps(rows, ensure_ascii=False), created_by=session.get("admin_email", ADMIN_OWNER_EMAIL)))
    db.session.commit()
    audit("admin:" + session.get("admin_email", ADMIN_OWNER_EMAIL), "cyber_shield.scan", None, json.dumps({"sites": len(rows), "warnings": sum(1 for x in rows if not x["http"] or x["score"] < 80)}))
    return redirect(url_for("cyber_shield_home"))
