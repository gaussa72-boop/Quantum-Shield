import os
import re
import json
import secrets
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
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

class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    origin = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    webhook_token = db.Column(db.String(96), nullable=True, unique=True)
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
        if not admin:
            session.clear()
            return redirect(url_for("admin_login"))
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

@app.get("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify(status="ok", service="ultima-membership-core", database="connected", ai_mode=AI_MODE, publish_mode=PUBLISH_MODE, publishing_requires_approval=(PUBLISH_MODE == "approval"))
    except Exception:
        app.logger.exception("Health check failed")
        return jsonify(status="degraded", database="unavailable"), 503

@app.get("/api/<slug>/config")
@limiter.limit("60 per minute")
def public_site_config(slug):
    site = site_for(slug)
    if not site:
        return jsonify(error="Webseite nicht gefunden oder nicht freigeschaltet."), 404
    return jsonify(site={"slug": site.slug, "name": site.name, "registration_enabled": True})

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
    member = Member(site_id=site.id, email=email, username=username, password_hash=generate_password_hash(password, method="scrypt"), display_name=str(data.get("display_name", username))[:120], role="superadmin" if ADMIN_OWNER_EMAIL and email == ADMIN_OWNER_EMAIL else "member", is_lifetime_premium=bool(PREMIUM_OWNER_EMAIL and email == PREMIUM_OWNER_EMAIL))
    db.session.add(member)
    db.session.commit()
    audit("member:" + email, "member.register", site.slug, str(member.id))
    return jsonify(ok=True, token=issue_token(member), member={"id": member.id, "email": member.email, "username": member.username, "display_name": member.display_name, "role": member.role, "is_lifetime_premium": member.is_lifetime_premium}), 201

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
    return jsonify(balance=member.credit_balance, currency="USD", credit_value="1 credit = 1 USD", prices=GENERATION_PRICES, wallet=BTC_ADDRESS, network=BTC_NETWORK, payment_enabled=bool(BTC_ADDRESS) and CRYPTO_TOPUPS_ENABLED)

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
    if member.is_lifetime_premium:
        return jsonify(ok=True, charged=0, balance=member.credit_balance, premium=True)
    if member.credit_balance < cost:
        return jsonify(error="Nicht genügend Credits.", required=cost, balance=member.credit_balance, upgrade_url="/credits"), 402
    member.credit_balance -= cost
    db.session.add(CreditLedger(site_id=site.id, member_id=member.id, delta=-cost, balance_after=member.credit_balance, reason=feature, reference=reference))
    db.session.commit()
    return jsonify(ok=True, charged=cost, balance=member.credit_balance)

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
    if not site or not site.webhook_token or not secrets.compare_digest(site.webhook_token, supplied):
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
    site.webhook_token = secrets.token_urlsafe(48)
    db.session.commit()
    audit(session.get("admin_email", "admin"), "site.integration_token_rotated", slug)
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

@app.get("/admin/login")
def admin_login():
    return render_template_string(LOGIN_HTML)

@app.post("/admin/login")
@limiter.limit("5 per 15 minutes")
def admin_login_post():
    data = request.form
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    # Owner SSO: accept the same credentials used on either Rothshild property.
    # Only the configured owner email with a verified superadmin member account
    # can bootstrap/update the central Admin record.
    admin = Admin.query.filter(func.lower(Admin.email) == email).first()
    if ADMIN_OWNER_EMAIL and email == ADMIN_OWNER_EMAIL:
        owner_members = (
            Member.query.join(Site, Member.site_id == Site.id)
            .filter(
                Site.slug.in_(("royal-palace-4r57", "business-real-estate-membership")),
                func.lower(Member.email) == email,
                Member.status == "active",
                Member.role == "superadmin",
            ).all()
        )
        verified_owner = next(
            (member for member in owner_members if check_password_hash(member.password_hash, password)),
            None,
        )
        if verified_owner:
            if not admin:
                admin = Admin(email=email, password_hash=verified_owner.password_hash, role="superadmin")
                db.session.add(admin)
            else:
                admin.password_hash = verified_owner.password_hash
                admin.role = "superadmin"
            db.session.commit()

    # Keep explicitly-created central administrators working as before.
    if not admin or not check_password_hash(admin.password_hash, password):
        return render_template_string(LOGIN_HTML, error="Anmeldedaten ungültig. Nutze dein aktives Rothshild-Inhaberkonto oder ein eingerichtetes ULTIMA-Admin-Konto."), 401

    session.clear()
    session["admin_id"] = admin.id
    session["admin_email"] = admin.email
    session["csrf"] = secrets.token_urlsafe(32)
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
    return render_template_string(ADMIN_HTML, sites=site_data, logs=logs, csrf=session["csrf"], total=Member.query.count(), payments=pending_payments, wallet=BTC_ADDRESS, orders=recent_orders, order_total=StoreOrder.query.count())


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
            details.append({"site": site.slug, "orders": StoreOrder.query.filter_by(site_id=site.id).count(), "last_order": latest.created_at.isoformat() if latest else None, "site_token_issued": bool(site.webhook_token)})
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
    db.session.add(Site(name=name, slug=slug, origin=origin, webhook_token=secrets.token_urlsafe(48)))
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
    return render_template_string(SITE_HTML, site=site, members=members, orders=orders, payments=payments, ledger=ledger, csrf=session["csrf"])

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
    if action == "disable":
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
    return jsonify(sites=[{"slug": s.slug, "name": s.name, "origin": s.origin, "members": Member.query.filter_by(site_id=s.id).count(), "active": s.is_active} for s in sites], total_members=Member.query.count())

SETUP_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA Setup</title><body style="font:16px system-ui;background:#090d18;color:#fff;max-width:520px;margin:8vh auto;padding:24px"><h1>ULTIMA · Erstadministrator</h1><p>Einmalige sichere Einrichtung. Das Setup-Token wird nicht gespeichert.</p><form id="f"><input id="email" type="email" placeholder="Admin-E-Mail" required style="display:block;width:100%;padding:12px;margin:10px 0"><input id="password" type="password" placeholder="Passwort (mind. 14 Zeichen)" required style="display:block;width:100%;padding:12px;margin:10px 0"><input id="token" type="password" placeholder="Setup-Token" required style="display:block;width:100%;padding:12px;margin:10px 0"><button style="padding:12px 18px">Administrator anlegen</button></form><pre id="out"></pre><script>f.onsubmit=async e=>{e.preventDefault();let r=await fetch('/setup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email.value,password:password.value,setup_token:token.value})});out.textContent=JSON.stringify(await r.json(),null,2)}</script></body></html>"""
LOGIN_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA Admin Login</title><body style="font:16px system-ui;background:#090d18;color:#fff;max-width:440px;margin:10vh auto;padding:24px"><h1>ULTIMA Control Center</h1><p>Administrator-Anmeldung</p>{% if error %}<p style="color:#ff9c9c">{{error}}</p>{% endif %}<form method="post"><input name="email" type="email" placeholder="E-Mail" required style="display:block;width:100%;padding:12px;margin:10px 0"><input name="password" type="password" placeholder="Passwort" required style="display:block;width:100%;padding:12px;margin:10px 0"><button style="padding:12px 18px">Anmelden</button></form></body></html>"""
ADMIN_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA Control Center</title><style>body{margin:0;background:#080b14;color:#edf1ff;font:15px system-ui}header{padding:22px 5vw;border-bottom:1px solid #26304a;display:flex;justify-content:space-between}main{max-width:1100px;margin:30px auto;padding:0 18px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}.card{background:#11182a;border:1px solid #26304a;border-radius:16px;padding:18px}input,button{padding:11px;border-radius:9px;border:1px solid #36415f;background:#0b1222;color:#fff;margin:4px}button{cursor:pointer;background:#293b68}a{color:#8ce4f0}small{color:#a8b4cd}.stat{font-size:28px;font-weight:800}</style><header><b>✦ ULTIMA CONTROL CENTER</b><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{csrf}}"><button>Abmelden</button></form></header><main><h1>Plattformverwaltung</h1><p><a href="/admin/credits">Credits- und Premium-Käufe verwalten →</a></p><p>Getrennte Konten pro Webseite · zentrale Übersicht · individuelle Admin-Rechte</p><div class="grid"><section class="card"><h3>Commerce Hub · Shopify-ähnlich</h3><p>Bestellungen, Rechnungen, Zahlungs- und Versandstatus sowie Shop-Webhooks zentral verwalten.</p><a href="#orders">Zu Bestellungen ↓</a></section><section class="card"><h3>Business Studio · Polsia-ähnlich</h3><p>Neue Webprojekte registrieren, bestehende Dienste anbinden und je Website eigene Inhalte und Einstellungen pflegen.</p><a href="#sites">Webseiten verwalten ↓</a></section><section class="card"><h3>Integrierte Automations-Bots</h3><p>Site Health · Member Guard · Order Monitor · Audit Watch. Prüfungen sind lesend; Zahlungen bleiben manuell.</p><form method="post" action="/admin/bots/run/site-health"><input type="hidden" name="csrf" value="{{csrf}}"><button>Site Health Bot starten</button></form><form method="post" action="/admin/bots/run/member-guard"><input type="hidden" name="csrf" value="{{csrf}}"><button>Member Guard starten</button></form><form method="post" action="/admin/bots/run/order-monitor"><input type="hidden" name="csrf" value="{{csrf}}"><button>Order Monitor starten</button></form><form method="post" action="/admin/bots/run/audit-watch"><input type="hidden" name="csrf" value="{{csrf}}"><button>Audit Watch starten</button></form><a href="/admin/credits">Credit-Review öffnen →</a></section></div><div class="grid"><section class="card"><small>MITGLIEDER GESAMT</small><div class="stat">{{total}}</div></section><section class="card"><small>PLATTFORMEN</small><div class="stat">{{sites|length}}</div></section></div><h2 id="sites">Webseiten & Geschäftsprojekte integrieren</h2><form method="post" action="/admin/sites" class="card"><input type="hidden" name="csrf" value="{{csrf}}"><input name="name" placeholder="Webseitenname" required><input name="slug" placeholder="slug-zum-beispiel" required><input name="origin" placeholder="https://deine-seite.onrender.com" required><button>Webseite hinzufügen</button></form><h2 id="orders">Bestellungen & Rechnungen · {{order_total}} Bestellungen</h2><section class="card"><table width="100%" cellpadding="8"><tr><th>Webseite</th><th>Bestellung</th><th>Kunde</th><th>Betrag</th><th>Zahlung</th><th>Versand</th><th>Rechnung</th></tr>{% for o in orders %}<tr><td>{{o.site.name}}</td><td>{{o.order_number}}</td><td>{{o.customer_name}}<br><small>{{o.customer_email}}</small></td><td>{{o.total_amount}} {{o.currency}}</td><td>{{o.payment_status}}</td><td>{{o.fulfillment_status}}</td><td><a href="/admin/order/{{o.id}}/invoice">Rechnung öffnen</a></td></tr>{% endfor %}</table></section><h2>Mitgliedschaften pro Webseite</h2><div class="grid">{% for item in sites %}<section class="card"><h3>{{item.site.name}}</h3><small>{{item.site.origin}}</small><div class="stat">{{item.count}}</div><p><a href="/admin/site/{{item.site.slug}}">Mitglieder verwalten →</a></p><small>{{item.admins}} lokale Administratoren · {{item.orders}} Bestellungen · {{'aktiv' if item.site.is_active else 'deaktiviert'}}</small></section>{% endfor %}</div><h2>Bitcoin-Zahlungen zur Prüfung</h2><section class="card"><p>Empfangsadresse: <b>{{wallet or "Noch nicht konfiguriert"}}</b> · Bitcoin mainnet</p>{% for p in payments %}<p>{{p.created_at}} · {{p.site.name}} · Mitglied #{{p.member_id}} · ${{p.amount_usd}} / {{p.credits}} Credits · TXID: <code>{{p.txid}}</code><form method="post" action="/admin/payment/{{p.id}}/approve" style="display:inline"><input type="hidden" name="csrf" value="{{csrf}}"><button>Zahlung bestätigen & Credits gutschreiben</button></form><form method="post" action="/admin/payment/{{p.id}}/reject" style="display:inline"><input type="hidden" name="csrf" value="{{csrf}}"><button>Ablehnen</button></form></p>{% else %}<small>Keine offenen Zahlungen.</small>{% endfor %}</section><h2>Letzte Verwaltungsaktionen</h2><section class="card">{% for log in logs %}<p><small>{{log.created_at}} · {{log.actor}} · {{log.action}} · {{log.site_slug or 'global'}}</small></p>{% else %}<small>Noch keine Aktionen.</small>{% endfor %}</section></main></html>"""
SITE_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{site.name}} · Mitglieder</title><body style="background:#090d18;color:#fff;font:15px system-ui;margin:0;padding:24px"><h1>{{site.name}} · Mitgliederverwaltung</h1><p>Konten dieser Webseite sind von allen anderen Plattformen getrennt.</p><h2>Website-Einstellungen</h2><form method="post" action="/admin/site/{{site.slug}}/settings"><input type="hidden" name="csrf" value="{{csrf}}"><label>Name <input name="name" value="{{site.name}}" required></label><label>Website-URL <input name="origin" value="{{site.origin}}" required></label><label><input type="checkbox" name="is_active" {% if site.is_active %}checked{% endif %}> Website aktiv</label><label><input type="checkbox" name="membership_enabled" {% if site.membership_enabled %}checked{% endif %}> Mitglieder/Credits aktiv</label><button>Website-Einstellungen speichern</button></form><p>Integrationsschlüssel: <code>{{site.webhook_token or "Noch nicht angelegt"}}</code></p><form method="post" action="/admin/site/{{site.slug}}/integration-token"><input type="hidden" name="csrf" value="{{csrf}}"><button>Webhook-Token neu erzeugen</button></form><h2>Bestellungen & Rechnungen</h2><table width="100%" cellpadding="9" style="border-collapse:collapse;background:#121a2b"><tr><th>Bestellung</th><th>Kunde</th><th>Betrag</th><th>Zahlung</th><th>Versand</th><th>Rechnung</th><th>Bearbeiten</th></tr>{% for o in orders %}<tr><td>{{o.order_number}}</td><td>{{o.customer_name}}<br>{{o.customer_email}}</td><td>{{o.total_amount}} {{o.currency}}</td><td>{{o.payment_status}}</td><td>{{o.fulfillment_status}}</td><td><a href="/admin/order/{{o.id}}/invoice">Öffnen</a></td><td><form method="post" action="/admin/order/{{o.id}}/update"><input type="hidden" name="csrf" value="{{csrf}}"><select name="payment_status"><option>{{o.payment_status}}</option><option>pending</option><option>paid</option><option>failed</option><option>refunded</option></select><select name="fulfillment_status"><option>{{o.fulfillment_status}}</option><option>processing</option><option>fulfilled</option><option>shipped</option><option>delivered</option><option>cancelled</option></select><button>Speichern</button></form></td></tr>{% endfor %}</table><h2>Credits-Käufe</h2><table width="100%" cellpadding="8" style="border-collapse:collapse;background:#121a2b"><tr><th>Betrag</th><th>Credits</th><th>TXID</th><th>Status</th></tr>{% for p in payments %}<tr><td>{{p.amount_usd}} USD</td><td>{{p.credits}}</td><td><code>{{p.txid}}</code></td><td>{{p.status}}</td></tr>{% endfor %}</table><h2>Credits & Premium-Käufe</h2><table width="100%" cellpadding="9" style="border-collapse:collapse;background:#121a2b"><tr><th>Mitglied</th><th>Betrag</th><th>Credits</th><th>TXID</th><th>Status</th><th>Aktion</th></tr>{% for p in payments %}<tr><td>{{p.member_id}}</td><td>{{p.amount_usd}} USD</td><td>{{p.credits}}</td><td><code>{{p.txid}}</code></td><td>{{p.status}}</td><td>{% if p.status == "pending" %}<form method="post" action="/admin/payment/{{p.id}}/approve"><input type="hidden" name="csrf" value="{{csrf}}"><button>Freigeben</button></form><form method="post" action="/admin/payment/{{p.id}}/reject"><input type="hidden" name="csrf" value="{{csrf}}"><button>Ablehnen</button></form>{% endif %}</td></tr>{% endfor %}</table><h2>Credit-Verlauf</h2><table width="100%" cellpadding="8"><tr><th>Datum</th><th>Mitglied</th><th>Änderung</th><th>Stand</th><th>Grund</th></tr>{% for x in ledger %}<tr><td>{{x.created_at}}</td><td>{{x.member_id}}</td><td>{{x.delta}}</td><td>{{x.balance_after}}</td><td>{{x.reason}}</td></tr>{% endfor %}</table><h2>Mitglieder</h2><table width="100%" cellpadding="9" style="border-collapse:collapse;background:#121a2b"><tr><th align="left">Benutzer</th><th>E-Mail</th><th>Rolle</th><th>Status</th><th>Aktion</th></tr>{% for m in members %}<tr><td>{{m.username}}</td><td>{{m.email}}</td><td>{{m.role}}</td><td>{{m.status}}</td><td><form method="post" action="/admin/site/{{site.slug}}/member/{{m.id}}"><input type="hidden" name="csrf" value="{{csrf}}"><button name="action" value="promote">Admin</button><button name="action" value="disable">Sperren</button><button name="action" value="enable">Aktivieren</button></form></td></tr>{% endfor %}</table></body></html>"""
INVOICE_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><title>Rechnung {{order.invoice_number or order.order_number}}</title><style>body{font:15px Arial;max-width:850px;margin:40px auto;color:#111}header{display:flex;justify-content:space-between;border-bottom:2px solid #222;padding-bottom:20px}table{width:100%;border-collapse:collapse}td,th{padding:10px;border-bottom:1px solid #ddd;text-align:left}.right{text-align:right}@media print{button{display:none}}</style><button onclick="print()">Drucken / als PDF speichern</button><header><div><h1>Rechnung</h1><b>{{site.name}}</b></div><div><b>{{order.invoice_number or order.order_number}}</b><br>{{order.created_at}}</div></header><p>Rechnung an: {{order.customer_name}} · {{order.customer_email}}</p><table><tr><th>Artikel</th><th>Menge</th><th>Einzelpreis</th><th>Gesamt</th></tr>{% for item in order.items_json or [] %}<tr><td>{{item.name}}</td><td>{{item.quantity}}</td><td>{{item.unit_price}}</td><td>{{item.total}}</td></tr>{% endfor %}</table><h2 class="right">Gesamt: {{order.total_amount}} {{order.currency}}</h2><p>Zahlungsstatus: {{order.payment_status}} · Bestellstatus: {{order.fulfillment_status}}</p>{% if order.invoice_url %}<p><a href="{{order.invoice_url}}">Originalrechnung öffnen</a></p>{% endif %}</html>"""
CREDITS_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Credits & Premium · ULTIMA</title><style>body{margin:0;background:#080b14;color:#edf1ff;font:15px system-ui;padding:24px}main{max-width:1200px;margin:auto}.card{background:#11182a;border:1px solid #26304a;border-radius:16px;padding:18px;margin:18px 0}table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #293650;text-align:left}button{padding:9px;border:0;border-radius:8px;background:#293b68;color:white}a{color:#8ce4f0}code{overflow-wrap:anywhere}</style><main><h1>Credits- und Premium-Verwaltung</h1><p><a href="/admin">← Zur zentralen Verwaltung</a></p><section class="card"><h2>Alle Aufladungen</h2><table><tr><th>Datum</th><th>Website</th><th>Mitglied</th><th>Betrag</th><th>Credits</th><th>TXID</th><th>Status</th><th>Aktion</th></tr>{% for p in payments %}<tr><td>{{p.created_at}}</td><td>{{p.site.name}}</td><td>{{p.member.email}}</td><td>{{p.amount_usd}} {{p.network}}</td><td>{{p.credits}}</td><td><code>{{p.txid}}</code></td><td>{{p.status}}</td><td>{% if p.status == "pending" %}<form method="post" action="/admin/payment/{{p.id}}/approve"><input type="hidden" name="csrf" value="{{csrf}}"><button>Bestätigen</button></form><form method="post" action="/admin/payment/{{p.id}}/reject"><input type="hidden" name="csrf" value="{{csrf}}"><button>Ablehnen</button></form>{% endif %}</td></tr>{% endfor %}</table></section><section class="card"><h2>Credit-Buchungen</h2><table><tr><th>Datum</th><th>Website</th><th>Mitglied-ID</th><th>Änderung</th><th>Stand</th><th>Grund</th></tr>{% for x in ledger %}<tr><td>{{x.created_at}}</td><td>{{x.site_id}}</td><td>{{x.member_id}}</td><td>{{x.delta}}</td><td>{{x.balance_after}}</td><td>{{x.reason}}</td></tr>{% endfor %}</table></section></main></html>"""
SITE_READONLY_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{site.name}} Admin</title><body style="background:#090d18;color:#fff;font:15px system-ui;padding:24px"><h1>{{site.name}} · Lokale Administration</h1><p>Angemeldet als {{admin_name}}. Diese Ansicht ist auf deine Webseite begrenzt.</p><p>{{members|length}} Mitglieder geladen. Vollständige Aktionen erfolgen über die zentrale Admin-Konsole.</p></body></html>"""

with app.app_context():
    db.create_all()
    site_columns = {col["name"] for col in inspect(db.engine).get_columns("site")}
    if "membership_enabled" not in site_columns:
        db.session.execute(text("ALTER TABLE site ADD COLUMN membership_enabled BOOLEAN NOT NULL DEFAULT TRUE"))
        db.session.commit()
    if "webhook_token" not in site_columns:
        db.session.execute(text("ALTER TABLE site ADD COLUMN webhook_token VARCHAR(96)"))
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
                    db.session.add(Site(slug=item["slug"], name=item["name"], origin=item["origin"], webhook_token=secrets.token_urlsafe(48), membership_enabled=item.get("membership_enabled", True)))
                else:
                    registered.name = item["name"]
                    registered.origin = item["origin"]
                    registered.membership_enabled = item.get("membership_enabled", True)
        db.session.commit()
    for registered_site in Site.query.filter_by(webhook_token=None).all():
        registered_site.webhook_token = secrets.token_urlsafe(48)
    if PREMIUM_OWNER_EMAIL:
        Member.query.filter(func.lower(Member.email) == PREMIUM_OWNER_EMAIL).update({"is_lifetime_premium": True}, synchronize_session=False)
    if ADMIN_OWNER_EMAIL:
        Member.query.filter(func.lower(Member.email) == ADMIN_OWNER_EMAIL).update({"role": "superadmin", "is_lifetime_premium": True}, synchronize_session=False)
    db.session.commit()
