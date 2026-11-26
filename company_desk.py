import os, json, secrets
from datetime import datetime, timezone, date
from decimal import Decimal, InvalidOperation
from flask import Blueprint, request, render_template_string, redirect, abort, session
from sqlalchemy import func

bp = Blueprint("ultima_company", __name__)

def _ctx():
    from app import db, admin_required, admin_csrf_ok, audit, ADMIN_OWNER_EMAIL, BTC_ADDRESS
    return db, audit, ADMIN_OWNER_EMAIL, BTC_ADDRESS

def _models():
    from app import db, StoreOrder, CryptoPayment, NetworkPremiumInvoice, WebsiteProject, GlobalUser
    class Invoice(db.Model):
        __tablename__ = "ultima_company_invoice"
        id=db.Column(db.Integer,primary_key=True)
        invoice_no=db.Column(db.String(80),unique=True,nullable=False,index=True)
        customer=db.Column(db.String(200),nullable=False)
        email=db.Column(db.String(255),default="",nullable=False)
        description=db.Column(db.String(1000),default="",nullable=False)
        amount=db.Column(db.Numeric(12,2),nullable=False)
        paid_amount=db.Column(db.Numeric(12,2),nullable=False,default=0)
        currency=db.Column(db.String(8),default="EUR",nullable=False)
        due_date=db.Column(db.Date,nullable=True)
        image_url=db.Column(db.String(1000),default="",nullable=False)
        merged_ids=db.Column(db.JSON,default=list,nullable=False)
        status=db.Column(db.String(24),default="open",nullable=False,index=True)
        created_at=db.Column(db.DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),nullable=False)
    class Loan(db.Model):
        __tablename__="ultima_company_loan_quote"
        id=db.Column(db.Integer,primary_key=True)
        principal=db.Column(db.Numeric(12,2),nullable=False)
        annual_rate=db.Column(db.Numeric(7,4),nullable=False)
        months=db.Column(db.Integer,nullable=False)
        markup_percent=db.Column(db.Numeric(7,4),default=14,nullable=False)
        monthly_payment=db.Column(db.Numeric(12,2),nullable=False)
        total_repayment=db.Column(db.Numeric(12,2),nullable=False)
        created_at=db.Column(db.DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),nullable=False)
    class Idea(db.Model):
        __tablename__="ultima_company_idea"
        id=db.Column(db.Integer,primary_key=True)
        project=db.Column(db.String(160),nullable=False)
        title=db.Column(db.String(240),nullable=False)
        details=db.Column(db.Text,nullable=False)
        source_url=db.Column(db.String(1000),default="",nullable=False)
        status=db.Column(db.String(24),default="review",nullable=False,index=True)
        created_at=db.Column(db.DateTime(timezone=True),default=lambda:datetime.now(timezone.utc),nullable=False)
    db.create_all()
    return db, Invoice, Loan, Idea, StoreOrder, CryptoPayment, NetworkPremiumInvoice, WebsiteProject, GlobalUser

PAGE = """<!doctype html><html lang=de><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>ULTIMA Company Desk</title><style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;background:#080d18;color:#eef3ff;font:15px system-ui}header{padding:20px 4vw;border-bottom:1px solid #263650;display:flex;justify-content:space-between}main{max-width:1400px;margin:28px auto;padding:0 18px}.muted{color:#9cabc4}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}.card{background:#111a2b;border:1px solid #2a3b58;border-radius:16px;padding:18px;margin:14px 0}.stat{font-size:28px;font-weight:800}input,select,textarea{background:#0b1322;color:#fff;border:1px solid #344762;border-radius:9px;padding:10px;width:100%;margin:5px 0 12px}button,.btn{background:#17627a;color:#fff;border:0;border-radius:9px;padding:10px 14px;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}button.paid{background:#16734d}table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #2a3b58;vertical-align:top}a{color:#8bd9ec}.tabs{display:flex;gap:8px;flex-wrap:wrap}.pill{padding:5px 9px;border-radius:99px;background:#253550}.formgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}.invoice{max-width:100px;max-height:80px}</style>
<header><b>◈ ULTIMA / COMPANY DESK</b><a href=/admin>← Control Center</a></header><main><h1>Unternehmensverwaltung</h1><p class=muted>Geschützter Adminbereich · zentrale Rechnungen, Shops, Wallet, Profile und Projektideen.</p>
<div class=grid><div class=card>OFFENE RECHNUNGEN<div class=stat>{{open_total}} €</div></div><div class=card>BEZAHLT<div class=stat>{{paid_total}} €</div></div><div class=card>SHOP-AUFTRÄGE<div class=stat>{{orders|length}}</div></div><div class=card>TXID-EINTRÄGE<div class=stat>{{payments|length+network_payments|length}}</div></div></div>
<nav class=tabs><a class=btn href=#invoices>Rechnungen</a><a class=btn href=#orders>Bestellungen</a><a class=btn href=#wallet>Wallet / TXID</a><a class=btn href=#sites>Websites</a><a class=btn href=#profiles>Profile</a><a class=btn href=#loans>Ratenrechner</a><a class=btn href=#ideas>KI-Ideen</a></nav>
<section class=card id=invoices><h2>Rechnungen</h2><form method=post action=/admin/company/invoice/new><input type=hidden name=csrf value="{{csrf}}"><div class=formgrid><label>Rechnungsnummer<input name=invoice_no required></label><label>Kunde<input name=customer required></label><label>E-Mail<input name=email type=email></label><label>Betrag EUR<input name=amount type=number min=.01 step=.01 required></label><label>Fälligkeit<input name=due_date type=date></label><label>Rechnungsbild-URL<input name=image_url type=url></label></div><label>Beschreibung<input name=description></label><button>Rechnung anlegen</button></form>
<p class=muted>Mehrere offene Rechnungen auswählen und zu einer Sammelrechnung zusammenführen.</p><form method=post action=/admin/company/invoice/merge><input type=hidden name=csrf value="{{csrf}}"><table><tr><th>Merge</th><th>Rechnung / Kunde</th><th>Bild</th><th>Gesamt</th><th>Bezahlt</th><th>Offen</th><th>Status / Aktion</th></tr>{% for x in invoices %}<tr><td>{% if x.status=='open' %}<input style="width:auto" type=checkbox name=invoice_ids value="{{x.id}}">{% endif %}</td><td><b>{{x.invoice_no}}</b><br>{{x.customer}}<br>{{x.description}}</td><td>{% if x.image_url %}<a href="{{x.image_url}}" target=_blank><img class=invoice src="{{x.image_url}}"></a>{% endif %}</td><td>{{x.amount}} {{x.currency}}</td><td>{{x.paid_amount}}</td><td>{{x.amount-x.paid_amount}}</td><td>{{x.status}} {% if x.status=='open' %}<form method=post action="/admin/company/invoice/{{x.id}}/paid"><input type=hidden name=csrf value="{{csrf}}"><input name=paid_amount type=number step=.01 min=.01 max="{{x.amount-x.paid_amount}}" placeholder=Teilbetrag required><button class=paid>Bezahlt buchen</button></form>{% endif %}</td></tr>{% endfor %}</table><button>Sammelrechnung erstellen</button></form></section>
<section class=card id=orders><h2>Shop-Bestellungen</h2><p class=muted>Alle über vorhandene Shop-Webhooks eingegangenen Bestellungen. Nicht verbundene Shops sind hier noch nicht sichtbar.</p><table><tr><th>Bestellung</th><th>Shop</th><th>Kunde</th><th>Betrag</th><th>Status</th><th>Aktion</th></tr>{% for o in orders %}<tr><td>{{o.order_number}}</td><td>{{o.site.name if o.site else o.source}}</td><td>{{o.customer_name}}<br>{{o.customer_email}}</td><td>{{o.total_amount}} {{o.currency}}</td><td>{{o.payment_status}}</td><td>{% if o.payment_status|lower not in ['paid','bezahlt','captured'] %}<form method=post action="/admin/company/order/{{o.id}}/paid"><input type=hidden name=csrf value="{{csrf}}"><button class=paid>Bezahlt markieren</button></form>{% endif %}{% if o.invoice_url %}<a href="{{o.invoice_url}}">Rechnung</a>{% endif %}</td></tr>{% endfor %}</table></section>
<section class=card id=wallet><h2>Wallet & TXIDs</h2><p>Wallet: <code>{{wallet}}</code></p><table><tr><th>Datum</th><th>Projekt</th><th>Betrag</th><th>TXID</th><th>Status</th></tr>{% for p in payments %}<tr><td>{{p.created_at}}</td><td>{{p.site.name if p.site else p.site_id}}</td><td>{{p.amount_usd}} USD</td><td>{{p.txid}}</td><td>{{p.status}}</td></tr>{% endfor %}{% for p in network_payments %}<tr><td>{{p.created_at}}</td><td>{{p.site_slug}}</td><td>{{p.amount_eur}} EUR</td><td>{{p.txid or '—'}}</td><td>{{p.status}} · {{p.confirmations}}</td></tr>{% endfor %}</table></section>
<section class=card id=sites><h2>Webseiten-Verzeichnis</h2><table><tr><th>Website</th><th>URL</th><th>Bearbeiten</th></tr>{% for s in sites %}<tr><td>{{s.name}}</td><td><a href="{{s.url}}" target=_blank>{{s.url}}</a></td><td><form method=post action="/admin/company/site/{{s.id}}"><input type=hidden name=csrf value="{{csrf}}"><input name=name value="{{s.name}}" required><input name=url value="{{s.url}}" required><input name=description value="{{s.description}}"><button>Speichern</button></form></td></tr>{% endfor %}</table></section>
<section class=card id=profiles><h2>Profile</h2><table><tr><th>Name</th><th>E-Mail</th><th>Rolle</th><th>Status</th><th>Ändern</th></tr>{% for u in users %}<tr><td>{{u.display_name or u.username}}</td><td>{{u.email}}</td><td>{{u.role}}</td><td>{{u.status}}</td><td><form method=post action="/admin/company/user/{{u.id}}"><input type=hidden name=csrf value="{{csrf}}"><select name=role><option>member</option><option>admin</option></select><select name=status><option>active</option><option>disabled</option></select><button>Speichern</button></form></td></tr>{% endfor %}</table></section>
<section class=card id=loans><h2>Raten- & Kreditrechner</h2><p class=muted>Rechenmodell, keine Kreditvermittlung oder Kreditzusage. 14 % Serviceaufschlag auf Finanzierungskosten wird ausgewiesen.</p><form method=post action=/admin/company/loan><input type=hidden name=csrf value="{{csrf}}"><div class=formgrid><label>Kreditbetrag<input name=principal type=number min=1 step=.01 required></label><label>Nominalzins p.a. %<input name=rate type=number min=0 max=100 step=.01 value=8></label><label>Laufzeit Monate<input name=months type=number min=1 max=360 value=24></label></div><button>Rate berechnen</button></form>{% if quote %}<h3>Monatsrate {{quote.monthly}} € · Gesamt {{quote.total}} €</h3>{% endif %}</section>
<section class=card id=ideas><h2>KI-Ideen & Update Matrix</h2><p class=muted>Ideen werden als Vorschläge protokolliert. Externe Webrecherche, autonome Codeänderung und Deployments sind nicht automatisch aktiv.</p><form method=post action=/admin/company/idea><input type=hidden name=csrf value="{{csrf}}"><div class=formgrid><label>Projekt<input name=project required></label><label>Idee<input name=title required></label><label>Quell-URL<input name=source_url type=url></label></div><label>Details<textarea name=details required></textarea></label><button>In Matrix vormerken</button></form><table><tr><th>Projekt</th><th>Idee</th><th>Quelle</th><th>Status</th></tr>{% for i in ideas %}<tr><td>{{i.project}}</td><td>{{i.title}}<br>{{i.details}}</td><td>{% if i.source_url %}<a href="{{i.source_url}}">Quelle</a>{% endif %}</td><td>{{i.status}}</td></tr>{% endfor %}</table></section>
</main></html>"""

def _guard():
    from app import admin_csrf_ok
    if not admin_csrf_ok(): abort(400)

@bp.get("/admin/company")
def home():
    from app import admin_required, StoreOrder, CryptoPayment, NetworkPremiumInvoice, WebsiteProject, GlobalUser, CompanyInvoice
    # Decorator is applied here to preserve the central owner-only admin session.
    return _home_render()
def _home_render():
    from app import admin_required, db, StoreOrder, CryptoPayment, NetworkPremiumInvoice, WebsiteProject, GlobalUser, ADMIN_OWNER_EMAIL, BTC_ADDRESS, app
    # Route wrapper's login check is enforced by the app's existing decorator below.
    return redirect("/admin/company/dashboard")

@bp.get("/admin/company/dashboard")
def dashboard():
    from app import admin_required, db, StoreOrder, CryptoPayment, NetworkPremiumInvoice, WebsiteProject, GlobalUser, ADMIN_OWNER_EMAIL, BTC_ADDRESS, session
    return _dashboard()
def _dashboard():
    from app import db, StoreOrder, CryptoPayment, NetworkPremiumInvoice, WebsiteProject, GlobalUser, ADMIN_OWNER_EMAIL, BTC_ADDRESS, session
    db, Invoice, Loan, Idea, StoreOrder, CryptoPayment, NetworkPremiumInvoice, WebsiteProject, GlobalUser = _models()
    invoices=Invoice.query.order_by(Invoice.created_at.desc()).limit(500).all()
    orders=StoreOrder.query.order_by(StoreOrder.created_at.desc()).limit(500).all()
    payments=CryptoPayment.query.order_by(CryptoPayment.created_at.desc()).limit(500).all()
    network_payments=NetworkPremiumInvoice.query.order_by(NetworkPremiumInvoice.created_at.desc()).limit(500).all()
    sites=WebsiteProject.query.order_by(WebsiteProject.name).all()
    users=GlobalUser.query.order_by(GlobalUser.created_at.desc()).limit(500).all()
    ideas=Idea.query.order_by(Idea.created_at.desc()).limit(200).all()
    op=sum((x.amount-x.paid_amount for x in invoices if x.status=="open"),Decimal("0"))
    pd=sum((x.paid_amount for x in invoices),Decimal("0"))
    return render_template_string(PAGE,invoices=invoices,orders=orders,payments=payments,network_payments=network_payments,sites=sites,users=users,ideas=ideas,open_total=f"{op:.2f}",paid_total=f"{pd:.2f}",wallet=BTC_ADDRESS or "Nicht konfiguriert",csrf=session.get("csrf",""),quote=None)

# Protect every endpoint with the same existing owner/admin gate.
from app import admin_required
home=admin_required(home)
dashboard=admin_required(dashboard)

@bp.post("/admin/company/invoice/new")
@admin_required
def invoice_new():
    _guard(); db,Invoice,*_= _models()
    try:
        amount=Decimal(request.form["amount"])
        if amount<=0: abort(400)
        due=date.fromisoformat(request.form["due_date"]) if request.form.get("due_date") else None
        db.session.add(Invoice(invoice_no=request.form["invoice_no"].strip(),customer=request.form["customer"].strip(),email=request.form.get("email","").strip(),description=request.form.get("description","")[:1000],amount=amount,due_date=due,image_url=request.form.get("image_url","").strip()))
        db.session.commit()
    except (InvalidOperation,ValueError,KeyError): db.session.rollback(); abort(400)
    return redirect("/admin/company/dashboard#invoices")

@bp.post("/admin/company/invoice/merge")
@admin_required
def invoice_merge():
    _guard(); db,Invoice,*_=_models(); ids=request.form.getlist("invoice_ids")
    rows=Invoice.query.filter(Invoice.id.in_(ids),Invoice.status=="open").all()
    if len(rows)<2 or len(rows)!=len(set(ids)) or len({x.currency for x in rows})!=1: abort(400)
    total=sum((x.amount-x.paid_amount for x in rows),Decimal("0"))
    merged=Invoice(invoice_no="MERGE-"+secrets.token_hex(5).upper(),customer="Sammelrechnung",description="Zusammengeführt: "+", ".join(x.invoice_no for x in rows),amount=total,merged_ids=[x.id for x in rows],status="open")
    for x in rows:x.status="merged"
    db.session.add(merged);db.session.commit()
    return redirect("/admin/company/dashboard#invoices")

@bp.post("/admin/company/invoice/<int:iid>/paid")
@admin_required
def invoice_paid(iid):
    _guard(); db,Invoice,*_=_models(); row=Invoice.query.get_or_404(iid)
    try: amount=Decimal(request.form.get("paid_amount",str(row.amount-row.paid_amount)))
    except InvalidOperation: abort(400)
    if amount<=0 or amount>row.amount-row.paid_amount: abort(400)
    row.paid_amount+=amount; row.status="paid" if row.paid_amount>=row.amount else "partial"; db.session.commit()
    return redirect("/admin/company/dashboard#invoices")

@bp.post("/admin/company/order/<int:oid>/paid")
@admin_required
def order_paid(oid):
    _guard(); db,Invoice,Loan,Idea,StoreOrder,*_=_models(); row=StoreOrder.query.get_or_404(oid)
    row.payment_status="paid"; row.updated_at=datetime.now(timezone.utc); db.session.commit()
    return redirect("/admin/company/dashboard#orders")

@bp.post("/admin/company/site/<int:sid>")
@admin_required
def site_edit(sid):
    _guard(); db,Invoice,Loan,Idea,StoreOrder,CryptoPayment,NetworkPremiumInvoice,WebsiteProject,*_=_models()
    row=WebsiteProject.query.get_or_404(sid); url=request.form.get("url","").strip()
    if not url.startswith("https://"): abort(400)
    row.name=request.form.get("name","").strip()[:120]; row.url=url[:500]; row.description=request.form.get("description","")[:2000]; db.session.commit()
    return redirect("/admin/company/dashboard#sites")

@bp.post("/admin/company/user/<int:uid>")
@admin_required
def user_edit(uid):
    _guard(); db,Invoice,Loan,Idea,StoreOrder,CryptoPayment,NetworkPremiumInvoice,WebsiteProject,GlobalUser=_models()
    row=GlobalUser.query.get_or_404(uid)
    if row.email.lower()==os.getenv("ADMIN_OWNER_EMAIL","").lower() or row.role=="owner": abort(403)
    role=request.form.get("role","member"); status=request.form.get("status","active")
    if role not in ("member","admin") or status not in ("active","disabled"): abort(400)
    row.role=role;row.status=status;db.session.commit();return redirect("/admin/company/dashboard#profiles")

@bp.post("/admin/company/loan")
@admin_required
def loan_calc():
    _guard(); db,Invoice,Loan,*_=_models()
    try:
        p=Decimal(request.form["principal"]); rate=Decimal(request.form["rate"])/100; months=int(request.form["months"])
        if p<=0 or rate<0 or rate>1 or months<1 or months>360: abort(400)
        r=rate/12; base=p/months if r==0 else p*r/(1-(1+r)**(-months))
        total=p+max(Decimal("0"),base*months-p)*Decimal("1.14")
        monthly=(total/months).quantize(Decimal(".01")); total=total.quantize(Decimal(".01"))
        db.session.add(Loan(principal=p,annual_rate=rate*100,months=months,markup_percent=14,monthly_payment=monthly,total_repayment=total));db.session.commit()
    except (InvalidOperation,ValueError,KeyError):abort(400)
    return redirect("/admin/company/dashboard#loans")

@bp.post("/admin/company/idea")
@admin_required
def idea_add():
    _guard(); db,Invoice,Loan,Idea,*_=_models()
    row=Idea(project=request.form.get("project","")[:160],title=request.form.get("title","")[:240],details=request.form.get("details","")[:10000],source_url=request.form.get("source_url","")[:1000])
    if not row.project or not row.title or not row.details:abort(400)
    db.session.add(row);db.session.commit();return redirect("/admin/company/dashboard#ideas")
