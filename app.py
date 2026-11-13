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
BTC_ADDRESS = "bc1qs0quxgqq26kawsq8al0kcxx3690jnp3a3zflce"
BTC_NETWORK = "Bitcoin mainnet"
GENERATION_PRICES = {"ai_generation": 1, "image_generation": 2, "video_generation": 5, "music_generation": 3, "game_generation": 25, "dlc_generation": 15, "mod_generation": 10}

class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    origin = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
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
    created_at = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    __table_args__ = (UniqueConstraint("site_id", "email", name="uq_member_site_email"), UniqueConstraint("site_id", "username", name="uq_member_site_username"))

class CryptoPayment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    site = db.relationship("Site")
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
    if not site:
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

@app.get("/membership-widget.js")
def membership_widget():
    return send_from_directory(os.path.dirname(__file__), "membership-widget.js", mimetype="application/javascript")

@app.get("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify(status="ok", service="ultima-membership-core", database="connected")
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
    member = Member(site_id=site.id, email=email, username=username, password_hash=generate_password_hash(password, method="scrypt"), display_name=str(data.get("display_name", username))[:120])
    db.session.add(member)
    db.session.commit()
    audit("member:" + email, "member.register", site.slug, str(member.id))
    return jsonify(ok=True, token=issue_token(member), member={"id": member.id, "email": member.email, "username": member.username, "display_name": member.display_name, "role": member.role}), 201

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
    return jsonify(ok=True, token=issue_token(member), member={"id": member.id, "email": member.email, "username": member.username, "display_name": member.display_name, "role": member.role})

@app.get("/api/<slug>/me")
def me(slug):
    site, member = current_member(slug)
    if not site:
        return jsonify(error="Webseite nicht gefunden."), 404
    if not member:
        return jsonify(error="Anmeldung erforderlich."), 401
    return jsonify(member={"id": member.id, "email": member.email, "username": member.username, "display_name": member.display_name, "bio": member.bio, "avatar_url": member.avatar_url, "role": member.role, "created_at": member.created_at.isoformat()})

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
    return jsonify(balance=member.credit_balance, currency="USD", credit_value="1 credit = 1 USD", prices=GENERATION_PRICES, wallet=BTC_ADDRESS, network=BTC_NETWORK)

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
    admin = Admin.query.filter(func.lower(Admin.email) == data.get("email", "").strip().lower()).first()
    if not admin or not check_password_hash(admin.password_hash, data.get("password", "")):
        return render_template_string(LOGIN_HTML, error="Anmeldedaten ungültig."), 401
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
        site_data.append({"site": site, "count": Member.query.filter_by(site_id=site.id).count(), "admins": Member.query.filter_by(site_id=site.id, role="site_admin").count()})
    logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(20).all()
    pending_payments = CryptoPayment.query.filter_by(status="pending").order_by(CryptoPayment.created_at.asc()).limit(100).all()
    return render_template_string(ADMIN_HTML, sites=site_data, logs=logs, csrf=session["csrf"], total=Member.query.count(), payments=pending_payments, wallet=BTC_ADDRESS)

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
    return render_template_string(SITE_HTML, site=site, members=members, csrf=session["csrf"])

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
ADMIN_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ULTIMA Control Center</title><style>body{margin:0;background:#080b14;color:#edf1ff;font:15px system-ui}header{padding:22px 5vw;border-bottom:1px solid #26304a;display:flex;justify-content:space-between}main{max-width:1100px;margin:30px auto;padding:0 18px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:14px}.card{background:#11182a;border:1px solid #26304a;border-radius:16px;padding:18px}input,button{padding:11px;border-radius:9px;border:1px solid #36415f;background:#0b1222;color:#fff;margin:4px}button{cursor:pointer;background:#293b68}a{color:#8ce4f0}small{color:#a8b4cd}.stat{font-size:28px;font-weight:800}</style><header><b>✦ ULTIMA CONTROL CENTER</b><form method="post" action="/admin/logout"><input type="hidden" name="csrf" value="{{csrf}}"><button>Abmelden</button></form></header><main><h1>Plattformverwaltung</h1><p>Getrennte Konten pro Webseite · zentrale Übersicht · individuelle Admin-Rechte</p><div class="grid"><section class="card"><small>MITGLIEDER GESAMT</small><div class="stat">{{total}}</div></section><section class="card"><small>PLATTFORMEN</small><div class="stat">{{sites|length}}</div></section></div><h2>Webseiten registrieren</h2><form method="post" action="/admin/sites" class="card"><input type="hidden" name="csrf" value="{{csrf}}"><input name="name" placeholder="Webseitenname" required><input name="slug" placeholder="slug-zum-beispiel" required><input name="origin" placeholder="https://deine-seite.onrender.com" required><button>Webseite hinzufügen</button></form><h2>Mitgliedschaften pro Webseite</h2><div class="grid">{% for item in sites %}<section class="card"><h3>{{item.site.name}}</h3><small>{{item.site.origin}}</small><div class="stat">{{item.count}}</div><p><a href="/admin/site/{{item.site.slug}}">Mitglieder verwalten →</a></p><small>{{item.admins}} lokale Administratoren · {{'aktiv' if item.site.is_active else 'deaktiviert'}}</small></section>{% endfor %}</div><h2>Bitcoin-Zahlungen zur Prüfung</h2><section class="card"><p>Empfangsadresse: <b>{{wallet}}</b> · Bitcoin mainnet</p>{% for p in payments %}<p>{{p.created_at}} · {{p.site.name}} · Mitglied #{{p.member_id}} · ${{p.amount_usd}} / {{p.credits}} Credits · TXID: <code>{{p.txid}}</code><form method="post" action="/admin/payment/{{p.id}}/approve" style="display:inline"><input type="hidden" name="csrf" value="{{csrf}}"><button>Zahlung bestätigen & Credits gutschreiben</button></form><form method="post" action="/admin/payment/{{p.id}}/reject" style="display:inline"><input type="hidden" name="csrf" value="{{csrf}}"><button>Ablehnen</button></form></p>{% else %}<small>Keine offenen Zahlungen.</small>{% endfor %}</section><h2>Letzte Verwaltungsaktionen</h2><section class="card">{% for log in logs %}<p><small>{{log.created_at}} · {{log.actor}} · {{log.action}} · {{log.site_slug or 'global'}}</small></p>{% else %}<small>Noch keine Aktionen.</small>{% endfor %}</section></main></html>"""
SITE_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{site.name}} · Mitglieder</title><body style="background:#090d18;color:#fff;font:15px system-ui;margin:0;padding:24px"><h1>{{site.name}} · Mitgliederverwaltung</h1><p>Konten dieser Webseite sind von allen anderen Plattformen getrennt.</p><table width="100%" cellpadding="9" style="border-collapse:collapse;background:#121a2b"><tr><th align="left">Benutzer</th><th>E-Mail</th><th>Rolle</th><th>Status</th><th>Aktion</th></tr>{% for m in members %}<tr><td>{{m.username}}</td><td>{{m.email}}</td><td>{{m.role}}</td><td>{{m.status}}</td><td><form method="post" action="/admin/site/{{site.slug}}/member/{{m.id}}"><input type="hidden" name="csrf" value="{{csrf}}"><button name="action" value="promote">Admin</button><button name="action" value="disable">Sperren</button><button name="action" value="enable">Aktivieren</button></form></td></tr>{% endfor %}</table></body></html>"""
SITE_READONLY_HTML = """<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{site.name}} Admin</title><body style="background:#090d18;color:#fff;font:15px system-ui;padding:24px"><h1>{{site.name}} · Lokale Administration</h1><p>Angemeldet als {{admin_name}}. Diese Ansicht ist auf deine Webseite begrenzt.</p><p>{{members|length}} Mitglieder geladen. Vollständige Aktionen erfolgen über die zentrale Admin-Konsole.</p></body></html>"""

with app.app_context():
    db.create_all()
    if "credit_balance" not in {col["name"] for col in inspect(db.engine).get_columns("member")}:
        db.session.execute(text("ALTER TABLE member ADD COLUMN credit_balance INTEGER NOT NULL DEFAULT 0"))
        db.session.commit()
    registry_path = os.path.join(os.path.dirname(__file__), "sites.json")
    if os.path.exists(registry_path):
        with open(registry_path, "r", encoding="utf-8") as registry_file:
            for item in json.load(registry_file):
                if item["slug"] not in {"royal-palace-4r57", "business-real-estate-membership"} and not Site.query.filter_by(slug=item["slug"]).first():
                    db.session.add(Site(slug=item["slug"], name=item["name"], origin=item["origin"]))
        db.session.commit()
