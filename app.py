# app.py
from flask import Flask, render_template, session, redirect, url_for, request, abort, jsonify
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
import traceback
import time
import json
import razorpay
from flask import jsonify
from decimal import Decimal, ROUND_HALF_UP

app = Flask(__name__)
app.secret_key = "mysecretkey"  # Needed for sessions

# ---------- DB Helpers ----------
# Default DB path (in production on Render you should mount a persistent disk, e.g. /var/data)
DB_PATH = os.getenv("DB_PATH", "/var/data/pcstore.db")

# Read keys from environment variables (do NOT hard-code secrets)
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

def _has_payment_keys() -> bool:
    return bool(RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET)

# Initialize a single global client if keys are present
rzp_client = None
if _has_payment_keys():
    try:
        rzp_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
        print("Razorpay client OK; key_id starts with:", (RAZORPAY_KEY_ID or "")[:6])
    except Exception as e:
        rzp_client = None
        print("ERROR initializing Razorpay client:", e)
else:
    print("WARN: Razorpay keys missing. Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET.")
    
def get_db():
    # Ensure directory exists only if DB_PATH contains a directory
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def list_tables_and_db_path():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
        tables = [r[0] for r in c.fetchall()]
    return {"db_path": DB_PATH, "tables": tables}

# ---------- Create / migrate tables ----------
def create_tables():
    """Create core tables if missing: users, builds, orders, products (stock handled separately)."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password_hash TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS builds (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                customer_name TEXT,
                whatsapp TEXT,
                comments TEXT,
                brand TEXT,
                processor TEXT,
                motherboard TEXT,
                ram TEXT,
                ssd TEXT,
                gpu TEXT,
                psu TEXT,
                cooling TEXT,
                aio TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                name TEXT,
                address TEXT,
                phone TEXT,
                items_json TEXT,
                total INTEGER
            )
        """)
        # Create products table without stock first; ensure_products_stock_column() will add stock if missing
        c.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT,
                price INTEGER,
                image TEXT,
                specs_json TEXT
            )
        """)
        conn.commit()

def ensure_products_stock_column():
    """Ensure 'products' table has a 'stock' integer column; add it if missing."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("PRAGMA table_info(products);")
        cols = {row[1] for row in c.fetchall()}
        if "stock" not in cols:
            c.execute("ALTER TABLE products ADD COLUMN stock INTEGER DEFAULT 0;")
            conn.commit()
            print("DB: Added 'stock' column to products.")
        else:
            print("DB: 'stock' column already present in products.")

def add_test_product():
    """Insert a test product (₹2) if it doesn't already exist."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM products WHERE id = 9999")
        if not c.fetchone():
            c.execute("""
                INSERT INTO products (id, name, price, image, specs_json, stock)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                9999,
                "Test Product ₹2",
                2,
                "test.jpg",  # make a dummy image in static if you want
                json.dumps(["This is a test product to check Razorpay"]),
                10,  # stock = 10
            ))
            conn.commit()
            print("✅ Test product (₹2) inserted.")
        else:
            print("ℹ️ Test product already exists.")

def migrate_builds_table():
    """Add optional columns to builds if missing (safe to run multiple times)."""
    with get_db() as conn:
        c = conn.cursor()
        c.execute("PRAGMA table_info(builds);")
        cols = {row[1] for row in c.fetchall()}
        to_add = []
        if "customer_name" not in cols:
            to_add.append(("customer_name", "TEXT"))
        if "whatsapp" not in cols:
            to_add.append(("whatsapp", "TEXT"))
        if "comments" not in cols:
            to_add.append(("comments", "TEXT"))
        for name, typ in to_add:
            c.execute(f"ALTER TABLE builds ADD COLUMN {name} {typ};")
        if to_add:
            conn.commit()

# Run schema creation / migration at startup
create_tables()
ensure_products_stock_column()
migrate_builds_table()
add_test_product()

# ---------- User management ----------
def register_user(email, password):
    email = (email or "").strip().lower()
    if not email:
        return False, "Email cannot be empty."
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)",
                      (email, generate_password_hash(password)))
            conn.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "This email is already registered."

def find_user(email):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email,))
        return c.fetchone()

def validate_login(email, password):
    row = find_user(email)
    if not row:
        return "not_found"
    pw_hash = row["password_hash"]
    try:
        return "ok" if check_password_hash(pw_hash, password) else "bad_password"
    except Exception as e:
        # If check_password_hash fails (unsupported hash), treat as bad_password but log
        print("Password check error:", e)
        return "bad_password"

# ---------- Build saving ----------
def save_build_to_db(build, email):
    try:
        print(f"DEBUG: save_build_to_db called at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("DEBUG: DB_PATH used by app:", DB_PATH)
        print("DEBUG: build payload:", build)
        print("DEBUG: email:", email)
        with get_db() as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO builds (
                    email, customer_name, whatsapp, comments,
                    brand, processor, motherboard, ram, ssd, gpu, psu, cooling, aio
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                email,
                build.get("customer_name"),
                build.get("whatsapp"),
                build.get("comments"),
                build.get("brand"),
                build.get("processor"),
                build.get("motherboard"),
                build.get("ram"),
                build.get("ssd"),
                build.get("gpu"),
                build.get("psu"),
                build.get("cooling"),
                build.get("aio"),
            ))
            conn.commit()
            print("DEBUG: build inserted, lastrowid:", c.lastrowid)
    except Exception as e:
        print("ERROR saving build:", e)
        traceback.print_exc()

# ---------- Auth guards ----------
def login_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapper

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "aayushtiwaryap@gmail.com")

def admin_required(view_func):
    @wraps(view_func)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login", next=request.path))
        if session.get("email") != ADMIN_EMAIL:
            return abort(403)
        return view_func(*args, **kwargs)
    return wrapper

@app.context_processor
def inject_admin_email():
    return {"admin_email": ADMIN_EMAIL}

@app.context_processor
def inject_cart_info():
    cart = session.get("cart", [])
    counts = {}
    for it in cart:
        counts[it["id"]] = counts.get(it["id"], 0) + 1
    cart_total = sum(item.get("price", 0) for item in cart)
    return {
        "cart_count": len(cart),
        "cart_total": cart_total,
        "cart_counts": counts,
        "cart_items": cart
    }

# ---------- Product seeding ----------
# Your prebuilt product definitions (used to seed DB on first run)
prebuilds = [
    {
        "id": 1,
        "name": "Entry Gaming",
        "price": 23000,
        "image": "entry.jpg",
        "stock": 3,
        "specs": [
            "Processor - Intel i5 4th Gen",
            "Motherboard - ZEBRONICS H61-NVMe Micro-ATX",
            "RAM - 8GB DDR3 1600MHz (2 sticks = 16GB)",
            "SSD - 512GB Gen 3 NVMe (3200MB/s Read, PCIe Gen 3×4)",
            "PSU - Ant Esports VS500L Non-Modular",
            "GPU - ASRock Phantom Gaming Radeon RX550 4GB GDDR5"
        ]
    },
    {
        "id": 2,
        "name": "Storm X 40",
        "price": 43000,
        "image": "storm.jpg",
        "stock": 2,
        "specs": [
            "Processor - AMD Ryzen 5 8500G",
            "Motherboard - B650M",
            "RAM - 16GB DDR5",
            "SSD - Kingston NV3 500GB",
            "PSU - 500W",
            "Case - Ant Esports"
        ]
    },
    {
        "id": 3,
        "name": "Inferno Core 60K",
        "price": 63000,
        "image": "inferno.jpg",
        "stock": 2,
        "specs": [
            "Processor - Intel Core i5-14400F",
            "Motherboard - ASUS B760M-AYW WiFi",
            "RAM - Crucial Pro 16GB DDR5-5600",
            "SSD - WD Blue SN5000 NVMe 1TB",
            "PSU - Cooler Master MWE 650 Bronze ATX 3.1",
            "Case - Circle Elegantor M3 Glass Tower"
        ]
    },
    {
        "id": 4,
        "name": "Shadow Blade 120000",
        "price": 124000,
        "image": "shadow.jpg",
        "stock": 1,
        "specs": [
            "Motherboard - ASUS TUF Gaming B850M-Plus WiFi M-ATX",
            "Cooler - Asus TUF Gaming LC II 360 ARGB",
            "Case - ASUS Glass TUF GT502 ATX",
            "PSU - ASUS TUF Gaming 850W Gold",
            "GPU - NVIDIA RTX 4070 Super"
        ]
    },
    {
        "id": 999,
        "name": "Razorpay Test Product (₹2)",
        "price": 2,
        "image": "test.png",
        "specs": ["Test purchase - ₹2"],
        "stock": 99
    }
]

def create_products_table():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY,
                name TEXT,
                price INTEGER,
                image TEXT,
                specs_json TEXT,
                stock INTEGER DEFAULT 0
            )
        """)
        conn.commit()

def init_products_from_prebuilds(seed_list=None):
    seed = seed_list if seed_list is not None else prebuilds
    try:
        print(f"DEBUG: init_products_from_prebuilds called at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        create_products_table()
        ensure_products_stock_column()
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM products")
            row = c.fetchone()
            count = row[0] if row else 0
            if count > 0:
                print(f"DEBUG: products table already has {count} row(s) — skipping seed.")
                return
            print("DEBUG: seeding products table...")
            for p in seed:
                specs_json = json.dumps(p.get("specs", []), ensure_ascii=False)
                c.execute("""
                    INSERT OR IGNORE INTO products (id, name, price, image, specs_json, stock)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (p["id"], p["name"], p["price"], p.get("image",""), specs_json, int(p.get("stock", 1))))
            conn.commit()
            print("DEBUG: products seeded.")
    except Exception as e:
        print("ERROR initializing products:", e)
        traceback.print_exc()

# Initialize products at startup (safe: only seeds if table empty)
init_products_from_prebuilds()

# ---------- Routes ----------
@app.route("/")
def home():
    # Show db-backed products on homepage
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, price, image, specs_json, stock FROM products ORDER BY id")
        rows = c.fetchall()
        prebuilds_db = []
        for r in rows:
            try:
                specs = json.loads(r["specs_json"]) if r["specs_json"] else []
                prebuilds_db.append({
                    "id": r["id"], "name": r["name"], "price": r["price"],
                    "image": r["image"], "specs": specs, "stock": r["stock"]
                })
            except Exception:
                specs = json.loads(r[4]) if r[4] else []
                prebuilds_db.append({
                    "id": r[0], "name": r[1], "price": r[2], "image": r[3], "specs": specs, "stock": r[5]
                })
    return render_template("home.html", prebuilds=prebuilds_db)

# Build form (anyone can view; submit requires login)
@app.route("/build", methods=["GET", "POST"])
def build():
    if request.method == "POST":
        session["my_build"] = {
            "customer_name": request.form.get("customer_name"),
            "whatsapp": request.form.get("whatsapp"),
            "comments": request.form.get("comments"),
            "brand": request.form.get("brand"),
            "processor": request.form.get("processor"),
            "motherboard": request.form.get("motherboard"),
            "ram": request.form.get("ram"),
            "ssd": request.form.get("ssd"),
            "gpu": request.form.get("gpu"),
            "psu": request.form.get("psu"),
            "cooling": request.form.get("cooling"),
            "aio": request.form.get("aio"),
        }
        print("DEBUG: Build received in /build:", session["my_build"])

        if not session.get("logged_in"):
            return redirect(url_for("login", next=url_for("build")))

        save_build_to_db(session["my_build"], session.get("email"))
        print("DEBUG: after save_build_to_db")
        return redirect(url_for("preview_build"))

    return render_template("build.html")

@app.route("/preview_build")
@login_required
def preview_build():
    my_build = session.get("my_build", None)
    return render_template("preview_build.html", my_build=my_build)

@app.route("/store")
def store():
    # get DB-backed products
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, price, image, specs_json, stock FROM products ORDER BY id")
        rows = c.fetchall()
    products = []
    for r in rows:
        try:
            specs = json.loads(r["specs_json"]) if r["specs_json"] else []
            products.append({"id": r["id"], "name": r["name"], "price": r["price"], "image": r["image"], "specs": specs, "stock": r["stock"]})
        except Exception:
            specs = json.loads(r[4]) if r[4] else []
            products.append({"id": r[0], "name": r[1], "price": r[2], "image": r[3], "specs": specs, "stock": r[5]})

    # build cart counts
    cart = session.get("cart", [])
    counts = {}
    for item in cart:
        counts[item["id"]] = counts.get(item["id"], 0) + 1

    return render_template("store.html", prebuilds=products, cart_counts=counts, cart_count=sum(counts.values()), cart_total=sum(i["price"] for i in cart))

# API add to cart (AJAX)
@app.route("/api/add_to_cart/<int:pc_id>", methods=["POST"])
@login_required
def api_add_to_cart(pc_id):
    # Check product and stock from DB
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, price, image, specs_json, stock FROM products WHERE id = ?", (pc_id,))
        row = c.fetchone()
        if not row:
            return jsonify({"ok": False, "error": "not_found"}), 404

        # handle sqlite3.Row or tuple
        try:
            pid = row["id"]; name = row["name"]; price = row["price"]
            image = row["image"]; specs_json = row["specs_json"]; stock = int(row["stock"] or 0)
        except Exception:
            pid, name, price, image, specs_json, stock = row

        specs = json.loads(specs_json) if specs_json else []

    # how many of this product does the current session already have?
    cart = session.get("cart", [])
    current_qty = sum(1 for it in cart if it.get("id") == pc_id)

    if stock <= current_qty:
        # no more available for this user (stock exhausted)
        return jsonify({"ok": False, "error": "sold_out", "stock": stock, "current_qty": current_qty}), 409

    # add snapshot to session cart
    cart.append({"id": pid, "name": name, "price": price, "specs": specs, "image": image})
    session["cart"] = cart

    # compute counts and totals
    counts = {}
    for it in cart:
        counts[it["id"]] = counts.get(it["id"], 0) + 1
    cart_count = sum(counts.values())
    cart_total = sum(it["price"] for it in cart)

    return jsonify({"ok": True, "cart_count": cart_count, "counts": counts, "cart_total": cart_total}), 200

# Fallback form add (non-JS)
@app.route("/add_to_cart/<int:pc_id>", methods=["POST"])
def add_to_cart(pc_id):
    # If not logged in, send user to login page and redirect back to store after login
    if not session.get("logged_in"):
        return redirect(url_for("login", next=url_for("store")))

    # Check stock in DB
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, name, price, image, specs_json, stock FROM products WHERE id = ?", (pc_id,))
        row = c.fetchone()
        if not row:
            session['error'] = "Product not found."
            return redirect(url_for("store"))

        try:
            stock = int(row["stock"] or 0); name = row["name"]; price = row["price"]
            image = row["image"]; specs = json.loads(row["specs_json"]) if row["specs_json"] else []
        except Exception:
            stock = int(row[5] or 0); name = row[1]; price = row[2]; image = row[3]; specs = json.loads(row[4]) if row[4] else []

    cart = session.get("cart", [])
    current_qty = sum(1 for it in cart if it.get("id") == pc_id)
    if stock <= current_qty:
        session['error'] = f"'{name}' is sold out or you already have the maximum available in your cart."
        return redirect(url_for("store"))

    # add to cart in session
    cart.append({"id": pc_id, "name": name, "price": price, "specs": specs, "image": image})
    session["cart"] = cart
    session.pop('error', None)
    return redirect(url_for("store"))

@app.route("/remove_from_cart/<int:index>", methods=["POST", "GET"])
@login_required
def remove_from_cart(index):
    cart = session.get("cart", [])
    if 0 <= index < len(cart):
        cart.pop(index)
        session["cart"] = cart
    return redirect(url_for("cart"))

@app.route("/api/remove_one_from_cart/<int:pc_id>", methods=["POST"])
@login_required
def api_remove_one_from_cart(pc_id):
    cart = session.get("cart", [])
    removed = False
    for i, it in enumerate(cart):
        if it.get("id") == pc_id:
            cart.pop(i)
            removed = True
            break
    session["cart"] = cart
    counts = {}
    for it in cart:
        counts[it["id"]] = counts.get(it["id"], 0) + 1
    cart_total = sum(item.get("price", 0) for item in cart)
    return jsonify({"ok": True, "removed": removed, "cart_count": len(cart), "counts": counts, "cart_total": cart_total})

@app.route("/shipping", methods=["GET", "POST"])
@login_required
def shipping():
    if not session.get("cart"):
        return redirect(url_for("store"))

    error = None
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        address = request.form.get("address", "").strip()
        phone = request.form.get("phone", "").strip()

        if not name or not address or not phone:
            error = "Please fill out all fields."
            return render_template("shipping.html", error=error)

        session["shipping"] = {"name": name, "address": address, "phone": phone}

        # Insert order
        try:
            cart = session.get("cart", [])
            shipping_info = session.get("shipping", {})
            total = sum(item.get("price", 0) for item in cart)

            if cart and shipping_info:
                with get_db() as conn:
                    c = conn.cursor()
                    c.execute("""
                        INSERT INTO orders (email, name, address, phone, items_json, total)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        session.get("email"),
                        shipping_info.get("name"),
                        shipping_info.get("address"),
                        shipping_info.get("phone"),
                        json.dumps(cart, ensure_ascii=False),
                        total
                    ))
                    conn.commit()
                    print("DEBUG: order inserted, lastrowid:", c.lastrowid)
            else:
                print("DEBUG: no cart or no shipping - skipping DB insert")
        except Exception as e:
            print("ERROR saving order:", e)
            traceback.print_exc()

        return redirect(url_for("checkout"))

    return render_template("shipping.html", error=error)


@app.post("/create_payment_order")
@login_required
def create_payment_order():
    if not _has_payment_keys() or rzp_client is None:
        return jsonify({"error": "Payment keys not configured"}), 400

    data = request.get_json(silent=True) or {}
    rupees = int(data.get("amount", 0))  # amount in ₹ from frontend
    if rupees < 1:
        return jsonify({"error": "Amount must be at least ₹1"}), 400

    amount_paise = rupees * 100
    try:
        order = rzp_client.order.create({
            "amount": amount_paise,
            "currency": "INR",
            "receipt": f"rcpt_{int(time.time())}",
            "payment_capture": 1
        })
        return jsonify({
            "ok": True,
            "order": order,                  # has id/amount/currency
            "key_id": RAZORPAY_KEY_ID,      # expose public key to frontend
            "local_order_id": order.get("id")
        })
    except Exception as e:
        print("ERROR creating Razorpay order:", e)
        return jsonify({"error": "Could not create payment order"}), 400
            
# Verify payment signature called by client after checkout
@app.route("/verify_payment", methods=["POST"])
@login_required
def verify_payment():
    """
    Expects JSON:
    { "razorpay_order_id": "...", "razorpay_payment_id": "...", "razorpay_signature": "...", "local_order_id": 123 }
    """
    data = request.get_json() or {}
    razorpay_order_id = data.get("razorpay_order_id")
    razorpay_payment_id = data.get("razorpay_payment_id")
    razorpay_signature = data.get("razorpay_signature")
    local_order_id = data.get("local_order_id")

    if not (razorpay_order_id and razorpay_payment_id and razorpay_signature and local_order_id):
        return jsonify({"ok": False, "error": "missing_parameters"}), 400

    try:
        # verify signature using razorpay util
        rzp_client.utility.verify_payment_signature({
            "razorpay_order_id": razorpay_order_id,
            "razorpay_payment_id": razorpay_payment_id,
            "razorpay_signature": razorpay_signature
        })
    except razorpay.errors.SignatureVerificationError as e:
        # verification failed
        return jsonify({"ok": False, "error": "signature_verification_failed"}), 400

    # mark order as paid in DB (update status, store payment id)
    with get_db() as conn:
        c = conn.cursor()
        # ensure columns exist: razorpay_payment_id, paid (you might have to add these via migration)
        try:
            c.execute("ALTER TABLE orders ADD COLUMN razorpay_payment_id TEXT")
        except sqlite3.OperationalError:
            pass
        try:
            c.execute("ALTER TABLE orders ADD COLUMN paid INTEGER DEFAULT 0")
        except sqlite3.OperationalError:
            pass

        c.execute("""
            UPDATE orders
            SET razorpay_payment_id = ?, paid = 1
            WHERE id = ? AND razorpay_order_id = ?
        """, (razorpay_payment_id, local_order_id, razorpay_order_id))
        conn.commit()

    return jsonify({"ok": True}), 200

@app.post("/payment_success")
@login_required
def payment_success():
    if not _has_payment_keys() or rzp_client is None:
        return jsonify({"ok": False, "error": "Payment keys not configured"}), 400

    payload = request.get_json(silent=True) or {}
    params = {
        "razorpay_order_id": payload.get("razorpay_order_id"),
        "razorpay_payment_id": payload.get("razorpay_payment_id"),
        "razorpay_signature": payload.get("razorpay_signature"),
    }
    try:
        rzp_client.utility.verify_payment_signature(params)
        return jsonify({"ok": True})
    except Exception as e:
        print("Payment verification error:", e)
        return jsonify({"ok": False, "error": "Verification failed"}), 400

@app.get("/_pay_diag")
@admin_required
def _pay_diag():
    return {
        "has_keys": _has_payment_keys(),
        "key_id_prefix": (RAZORPAY_KEY_ID[:6] + "****") if RAZORPAY_KEY_ID else None
    }

@app.route("/cart")
@login_required
def cart():
    cart = session.get("cart", [])
    total = sum(item.get("price", 0) for item in cart)
    return render_template("cart.html", cart=cart, total=total)

@app.route("/checkout")
@login_required
def checkout():
    cart = session.get("cart", [])
    shipping = session.get("shipping", {})
    total = sum(item.get("price", 0) for item in cart)

    # Save order if we have shipping info
    if cart and shipping:
        with get_db() as conn:
            c = conn.cursor()

            # Count quantities per product id
            counts = {}
            for it in cart:
                counts[it["id"]] = counts.get(it["id"], 0) + 1

            # ensure stock is sufficient for all items (re-check)
            for pid, qty in counts.items():
                c.execute("SELECT stock FROM products WHERE id = ?", (pid,))
                row = c.fetchone()
                if not row:
                    raise Exception(f"Product {pid} not found during checkout")
                stock = row["stock"] if isinstance(row, sqlite3.Row) else row[0]
                if stock < qty:
                    raise Exception(f"Not enough stock for product id {pid} (have {stock}, need {qty})")

            # decrement stock now (atomic-ish inside this connection)
            for pid, qty in counts.items():
                c.execute("UPDATE products SET stock = stock - ? WHERE id = ?", (qty, pid))

            # insert order record
            c.execute("""
                INSERT INTO orders (email, name, address, phone, items_json, total)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session.get("email"),
                shipping.get("name"),
                shipping.get("address"),
                shipping.get("phone"),
                json.dumps(cart, ensure_ascii=False),
                total
            ))

            conn.commit()   # ✅ must be indented inside the "with" block

    # Clear cart & shipping after checkout
    session["cart"] = []
    session.pop("shipping", None)

    return render_template("checkout.html", total=total)

@app.route("/submissions")
@login_required
def submissions():
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM builds")
        builds = c.fetchall()
    return render_template("submissions.html", builds=builds)

# ---------- Auth routes ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if session.get("logged_in"):
        dest = request.args.get("next") or url_for("home")
        return redirect(dest)

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        status = validate_login(email, password)
        if status == "ok":
            session["logged_in"] = True
            session["email"] = email
            dest = request.args.get("next") or url_for("home")
            return redirect(dest)
        elif status == "not_found":
            return redirect(url_for("register", email=email))
        else:
            error = "Incorrect password. Please try again."

    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    prefill_email = request.args.get("email", "")

    if request.method == "POST":
        raw_email = request.form.get("email", "")
        password = request.form.get("password", "")
        email = raw_email.strip().lower()

        if not email:
            error = "Please enter your email."
            return render_template("register.html", error=error, success=success, prefill_email="")
        if "@" not in email or "." not in email.split("@")[-1]:
            error = "Please enter a valid email address."
            return render_template("register.html", error=error, success=success, prefill_email=email)
        if not password:
            error = "Please enter a password."
            return render_template("register.html", error=error, success=success, prefill_email=email)

        ok, msg = register_user(email, password)
        if ok:
            session["logged_in"] = True
            session["email"] = email
            dest = request.args.get("next") or url_for("home")
            return redirect(dest)
        else:
            error = msg or "Registration failed. Please try again."
            return render_template("register.html", error=error, success=success, prefill_email=email)

    return render_template("register.html", error=error, success=success, prefill_email=prefill_email)

# ---------- Admin helpers & routes ----------
@app.route("/admin/debug")
@admin_required
def admin_debug():
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT COUNT(*) FROM builds"); builds_count = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM orders"); orders_count = c.fetchone()[0]
            c.execute("SELECT id, email, brand, processor FROM builds ORDER BY id DESC LIMIT 5")
            recent_builds = [list(r) for r in c.fetchall()]
        return {"db_path": DB_PATH, "builds_count": builds_count, "orders_count": orders_count, "recent_builds": recent_builds}
    except Exception as e:
        return {"error": str(e)}, 500

@app.route("/admin/initdb")
@admin_required
def admin_initdb():
    create_tables()
    ensure_products_stock_column()
    info = list_tables_and_db_path()
    return f"<pre>DB Path: {info['db_path']}\nTables: {info['tables']}</pre>"

@app.route("/admin", methods=["GET"])
@admin_required
def admin():
    """Render admin dashboard: products with stock, builds, orders."""
    try:
        # fetch products
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id, name, price, image, specs_json, stock FROM products ORDER BY id")
            prod_rows = c.fetchall()
            products = []
            for r in prod_rows:
                try:
                    specs = json.loads(r["specs_json"]) if r["specs_json"] else []
                    products.append({
                        "id": r["id"],
                        "name": r["name"],
                        "price": r["price"],
                        "image": r["image"],
                        "specs": specs,
                        "stock": r["stock"],
                    })
                except Exception:
                    specs = json.loads(r[4]) if r[4] else []
                    products.append({
                        "id": r[0],
                        "name": r[1],
                        "price": r[2],
                        "image": r[3],
                        "specs": specs,
                        "stock": r[5],
                    })

        # fetch builds
        with get_db() as conn:
            c = conn.cursor()
            c.execute("""SELECT id, email, customer_name, whatsapp, comments, brand, processor, motherboard, ram, ssd, gpu, psu, cooling, aio
                         FROM builds ORDER BY id DESC""")
            build_rows = c.fetchall()
            builds = []
            for r in build_rows:
                try:
                    b = {k: r[k] for k in r.keys()}
                except Exception:
                    b = {
                        "id": r[0], "email": r[1], "customer_name": r[2], "whatsapp": r[3],
                        "comments": r[4], "brand": r[5], "processor": r[6], "motherboard": r[7],
                        "ram": r[8], "ssd": r[9], "gpu": r[10], "psu": r[11], "cooling": r[12], "aio": r[13]
                    }
                builds.append(b)

        # fetch orders
        with get_db() as conn:
            c = conn.cursor()
            c.execute("SELECT id, email, name, address, phone, items_json, total FROM orders ORDER BY id DESC")
            order_rows = c.fetchall()
            orders = []
            for r in order_rows:
                try:
                    items_json = r["items_json"]
                except Exception:
                    items_json = r[5]
                parsed = []
                if items_json:
                    try:
                        parsed = json.loads(items_json)
                    except Exception:
                        parsed = [items_json]
                try:
                    oid = r["id"]; email = r["email"]; name = r["name"]; address = r["address"]
                    phone = r["phone"]; total = r["total"]
                except Exception:
                    oid, email, name, address, phone, _, total = r
                orders.append({
                    "id": oid,
                    "email": email,
                    "name": name,
                    "address": address,
                    "phone": phone,
                    "items_list": parsed,
                    "total": total
                })

        return render_template("admin.html", products=products, builds=builds, orders=orders)
    except Exception as e:
        print("ERROR in /admin:", e)
        traceback.print_exc()
        return "Admin page error - check server logs", 500

@app.route("/admin/update_stock", methods=["POST"])
@admin_required
def admin_update_stock():
    """Update a single product's stock (from admin dashboard)."""
    try:
        product_id = int(request.form.get("product_id"))
        new_stock = int(request.form.get("stock"))
    except Exception:
        return redirect(url_for("admin"))

    with get_db() as conn:
        c = conn.cursor()
        c.execute("UPDATE products SET stock = ? WHERE id = ?", (new_stock, product_id))
        conn.commit()

    return redirect(url_for("admin"))

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    print("🚀 Flask app started (email/password auth).")
    app.run(debug=True)
