import os, random, secrets
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from dotenv import load_dotenv
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, abort)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()
BANK_NAME = "Capybank"
MAX_ATTEMPTS = 3
PER_TXN_LIMIT = Decimal("50000")
DAILY_WITHDRAW_LIMIT = Decimal("20000")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-only-change-me")
db_url = os.getenv("DATABASE_URL", "sqlite:///capybank.db")
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)
elif db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
app.config.update(
    SQLALCHEMY_DATABASE_URI=db_url,
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.getenv("RENDER")),
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=5),  # idle timeout
)
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    account_no = db.Column(db.String(32), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="customer")
    pin_hash = db.Column(db.String(256), nullable=False)
    balance = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    must_change_pin = db.Column(db.Boolean, default=True)
    failed_attempts = db.Column(db.Integer, default=0)
    locked = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    kind = db.Column(db.String(12))  # deposit / withdraw
    amount = db.Column(db.Numeric(12, 2))
    balance_after = db.Column(db.Numeric(12, 2))
    ref = db.Column(db.String(16), unique=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(40))
    event = db.Column(db.String(40))
    detail = db.Column(db.String(200))
    ip = db.Column(db.String(45))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


def audit(username, event, detail=""):
    db.session.add(AuditLog(username=username, event=event, detail=detail,
                            ip=request.headers.get("X-Forwarded-For", request.remote_addr)))


def init_db():
    with app.app_context():
        try:
            db.create_all()
        except Exception:  # another worker won the race
            db.session.rollback()
        name = os.getenv("ADMIN_USERNAME", "admin")
        if not User.query.filter_by(role="admin").first():
            pin = os.getenv("ADMIN_PIN", "Admin#2026")
            db.session.add(User(account_no=name, name="Bank Admin", role="admin",
                                pin_hash=generate_password_hash(pin), must_change_pin=False))
            db.session.commit()


@app.template_filter("peso")
def peso(v):
    return f"₱{Decimal(v):,.2f}"


@app.template_filter("stamp")
def stamp(d):
    return d.strftime("%b %d, %Y %I:%M %p")


@app.context_processor
def inject():
    session.setdefault("csrf", secrets.token_hex(16))
    return dict(csrf=session["csrf"], bank=BANK_NAME)


@app.before_request
def csrf_protect():
    if request.method == "POST":
        sent = request.headers.get("X-CSRF") or request.form.get("csrf")
        if not sent or sent != session.get("csrf"):
            abort(400, "Session expired. Refresh the page and try again.")


def current_user():
    uid = session.get("uid")
    return db.session.get(User, uid) if uid else None


def login_required(role):
    def deco(fn):
        @wraps(fn)
        def wrap(*a, **k):
            u = current_user()
            if not u:
                flash("Please sign in.", "error")
                return redirect(url_for("login"))
            if u.role != role:
                return redirect(url_for("home"))
            if u.must_change_pin and request.endpoint != "change_pin":
                return redirect(url_for("change_pin"))
            return fn(u, *a, **k)
        return wrap
    return deco


def check_pin(u, pin):
    """Verify a PIN, count failures and lock customer accounts after 3."""
    if u.locked:
        return False, "Account locked. Please ask the bank admin to unlock it."
    if check_password_hash(u.pin_hash, pin or ""):
        u.failed_attempts = 0
        return True, ""
    if u.role == "customer":
        u.failed_attempts += 1
        audit(u.account_no, "bad_pin", f"attempt {u.failed_attempts}")
        if u.failed_attempts >= MAX_ATTEMPTS:
            u.locked = True
            audit(u.account_no, "locked", "too many wrong PINs")
            return False, "Too many wrong PINs. Account locked."
        return False, f"Wrong PIN. {MAX_ATTEMPTS - u.failed_attempts} attempt(s) left."
    return False, "Wrong PIN."


def valid_new_pin(pin):
    return pin.isdigit() and 4 <= len(pin) <= 6


@app.get("/")
def home():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    return redirect(url_for("admin" if u.role == "admin" else "dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ident = request.form.get("account", "").strip()
        pin = request.form.get("pin", "")
        u = User.query.filter_by(account_no=ident).first()
        if not u:
            audit(ident[:40], "login_unknown")
            db.session.commit()
            flash("Account number or PIN is incorrect.", "error")
            return render_template("login.html")
        ok, msg = check_pin(u, pin)
        if not ok:
            db.session.commit()
            flash(msg if u.locked else "Account number or PIN is incorrect. " + msg, "error")
            return render_template("login.html")
        audit(u.account_no, "login")
        db.session.commit()
        csrf = secrets.token_hex(16)
        session.clear()
        session.update(uid=u.id, csrf=csrf)
        session.permanent = True
        return redirect(url_for("home"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    u = current_user()
    if u:
        audit(u.account_no, "logout")
        db.session.commit()
    idle = request.args.get("idle")
    session.clear()
    flash("You were signed out after being idle." if idle else "You are signed out.", "info")
    return redirect(url_for("login"))


@app.get("/dashboard")
@login_required("customer")
def dashboard(u):
    txns = (Transaction.query.filter_by(user_id=u.id)
            .order_by(Transaction.id.desc()).limit(15).all())
    return render_template("dashboard.html", u=u, txns=txns,
                           per_txn=PER_TXN_LIMIT, daily=DAILY_WITHDRAW_LIMIT)


@app.post("/transact")
@login_required("customer")
def transact(_u):
    d = request.get_json(silent=True) or {}
    u = db.session.execute(db.select(User).where(User.id == _u.id)
                           .with_for_update()).scalar_one()
    ok, msg = check_pin(u, str(d.get("pin", "")))  # PIN re-entry on EVERY transaction
    if not ok:
        db.session.commit()
        resp = jsonify(ok=False, error=msg, locked=u.locked)
        if u.locked:
            session.clear()
        return resp, 403
    kind = d.get("kind")
    try:
        amt = Decimal(str(d.get("amount", ""))).quantize(Decimal("0.01"))
    except InvalidOperation:
        return jsonify(ok=False, error="Enter a valid amount."), 400
    if kind not in ("deposit", "withdraw") or amt <= 0:
        return jsonify(ok=False, error="Enter an amount above zero."), 400
    if amt > PER_TXN_LIMIT:
        return jsonify(ok=False, error=f"Limit per transaction is {peso(PER_TXN_LIMIT)}."), 400
    if kind == "withdraw":
        if amt > u.balance:
            return jsonify(ok=False, error="Insufficient balance."), 400
        start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        used = db.session.query(db.func.coalesce(db.func.sum(Transaction.amount), 0)).filter(
            Transaction.user_id == u.id, Transaction.kind == "withdraw",
            Transaction.created_at >= start).scalar()
        if Decimal(used) + amt > DAILY_WITHDRAW_LIMIT:
            return jsonify(ok=False, error=f"Daily withdrawal limit of {peso(DAILY_WITHDRAW_LIMIT)} reached."), 400
        u.balance -= amt
    else:
        u.balance += amt
    t = Transaction(user_id=u.id, kind=kind, amount=amt, balance_after=u.balance,
                    ref=secrets.token_hex(4).upper())
    db.session.add(t)
    audit(u.account_no, kind, f"{amt} ref {t.ref}")
    db.session.commit()
    return jsonify(ok=True, ref=t.ref, kind=kind, amount=peso(amt), balance=peso(u.balance),
                   when=stamp(t.created_at), logout=bool(d.get("logout_after")))


@app.route("/change-pin", methods=["GET", "POST"])
def change_pin():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    if request.method == "POST":
        cur, new, conf = (request.form.get(k, "") for k in ("current", "new", "confirm"))
        ok, msg = check_pin(u, cur)
        if not ok:
            db.session.commit()
            flash(msg, "error")
        elif u.role == "customer" and not valid_new_pin(new):
            flash("New PIN must be 4 to 6 digits.", "error")
        elif u.role == "admin" and len(new) < 8:
            flash("Admin password must be at least 8 characters.", "error")
        elif new != conf:
            flash("The new PINs don't match.", "error")
        elif new == cur:
            flash("Pick a PIN different from your current one.", "error")
        else:
            u.pin_hash = generate_password_hash(new)
            u.must_change_pin = False
            audit(u.account_no, "pin_changed")
            db.session.commit()
            flash("PIN changed.", "success")
            return redirect(url_for("home"))
    return render_template("change_pin.html", u=u)


def default_pin():
    return f"{random.SystemRandom().randint(0, 9999):04d}"


@app.get("/admin")
@login_required("admin")
def admin(u):
    customers = User.query.filter_by(role="customer").order_by(User.id.desc()).all()
    logs = AuditLog.query.order_by(AuditLog.id.desc()).limit(25).all()
    total = sum((c.balance for c in customers), Decimal(0))
    return render_template("admin.html", u=u, customers=customers, logs=logs, total=total)


@app.post("/admin/create")
@login_required("admin")
def admin_create(u):
    name = request.form.get("name", "").strip()
    if not name:
        flash("Enter the customer's name.", "error")
        return redirect(url_for("admin"))
    while True:
        acct = "2026" + "".join(random.choices("0123456789", k=6))
        if not User.query.filter_by(account_no=acct).first():
            break
    pin = default_pin()
    db.session.add(User(account_no=acct, name=name[:80], pin_hash=generate_password_hash(pin)))
    audit(u.account_no, "customer_created", acct)
    db.session.commit()
    flash(f"Created {name}. Account {acct}, default PIN {pin}. Share it now; it won't be shown again.", "success")
    return redirect(url_for("admin"))


@app.post("/admin/reset/<int:uid>")
@login_required("admin")
def admin_reset(u, uid):
    c = db.get_or_404(User, uid)
    if c.role != "customer":
        abort(403)
    pin = default_pin()
    c.pin_hash, c.must_change_pin = generate_password_hash(pin), True
    c.locked, c.failed_attempts = False, 0
    audit(u.account_no, "pin_reset", c.account_no)
    db.session.commit()
    flash(f"{c.name} unlocked. New default PIN {pin}.", "success")
    return redirect(url_for("admin"))


init_db()
if __name__ == "__main__":
    app.run(debug=True)
