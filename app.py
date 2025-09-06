from flask import Flask, render_template, session, redirect, url_for, request, abort
import os
import sqlite3
from functools import wraps
import json
from werkzeug.security import generate_password_hash, check_password_hash
import traceback, time

app = Flask(__name__)
app.secret_key = "mysecretkey"  # Needed for sessions

# ---------- DB Helpers ----------
# Use a stable, writable DB path (Render: mount a Persistent Disk at /var/data)
DB_PATH = os.getenv("DB_PATH", "/var/data/pcstore.db")

def get_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
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

def create_orders_table():
    # ✅ use get_db() so it writes to the same DB_PATH
    with get_db() as conn:
        c = conn.cursor()
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
        conn.commit()

def create_tables():
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
        conn.commit()

def ensure_users_schema():
    """Ensure users table has (email, password_hash). If not, migrate."""
    with get_db() as conn:
        c = conn.cursor()
        # Create table if it doesn't exist
        c.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password_hash TEXT
            )
        """)
        # Inspect current columns
        c.execute("PRAGMA table_info(users)")
        cols = {row[1] for row in c.fetchall()}
        required = {"email", "password_hash"}
        if required.issubset(cols):
            return  # schema OK

        # Schema is wrong (likely old 'username', 'password'). Migrate safely.
        c.execute("ALTER TABLE users RENAME TO users_backup")
        c.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE,
                password_hash TEXT
            )
        """)
        # Try to copy what we can
        try:
            c.execute("SELECT username, password FROM users_backup")
            for username, password in c.fetchall():
                # password may be plain text from old schema; those users may need reset
                c.execute(
                    "INSERT OR IGNORE INTO users (email, password_hash) VALUES (?, ?)",
                    (username, password)
                )
        except sqlite3.OperationalError:
            # old table didn't have username/password — nothing to copy
            pass
        c.execute("DROP TABLE users_backup")
        conn.commit()

def migrate_builds_table():
    # add new columns if they don't exist yet
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
        conn.commit()

# ✅ Run at startup (must be at top-level, NOT in if __name__ == "__main__")
create_tables()
create_orders_table()
ensure_users_schema()
migrate_builds_table()

# ---------- User management ----------
def register_user(email: str, password: str):
    email = (email or "").strip().lower()
    if not email:
        return False, "Email cannot be empty."
    try:
        with get_db() as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                (email, generate_password_hash(password)),
            )
            conn.commit()
        return True, None
    except sqlite3.IntegrityError:
        return False, "This email is already registered."

def find_user(email: str):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, email, password_hash FROM users WHERE email = ?", (email,))
        return c.fetchone()

def validate_login(email: str, password: str) -> str:
    row = find_user(email)
    if not row:
        return "not_found"
    _, _, pw_hash = row
    return "ok" if check_password_hash(pw_hash, password) else "bad_password"

def save_build_to_db(build: dict, email: str):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            INSERT INTO builds (
                email, customer_name, whatsapp, comments,
                brand, processor, motherboard, ram, ssd, gpu, psu, cooling, aio
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    cart_total = sum(item["price"] for item in cart)
    return {
        "cart_count": len(cart),
        "cart_total": cart_total,
        "cart_counts": counts,
        "cart_items": cart
    }    
# ---------- Sample Data ----------
prebuilds = [
    {
        "id": 1,
        "name": "Entry Gaming",
        "price": 23000,
        "image": "entry.jpg",
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
        "specs": [
            "Motherboard - ASUS TUF Gaming B850M-Plus WiFi M-ATX",
            "Cooler - Asus TUF Gaming LC II 360 ARGB",
            "Case - ASUS Glass TUF GT502 ATX",
            "PSU - ASUS TUF Gaming 850W Gold",
            "GPU - NVIDIA RTX 4070 Super"
        ]
    }
]

# ---------- Routes ----------
@app.route("/")
def home():
    return render_template("home.html", prebuilds=prebuilds)

# Anyone can view the build page, but submitting requires login
@app.route("/build", methods=["GET", "POST"])
def build():
    if request.method == "POST":
        if not session.get("logged_in"):
            return redirect(url_for("login", next=url_for("build")))

        session["my_build"] = {
            "customer_name": request.form.get("customer_name", "").strip(),
            "whatsapp": request.form.get("whatsapp", "").strip(),
            "comments": request.form.get("comments", "").strip(),
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

        # ✅ Optional minimal check for WhatsApp number
        wa = session["my_build"]["whatsapp"]
        if not wa or not wa.replace("+", "").replace(" ", "").isdigit():
            error = "Please enter a valid WhatsApp number."
            return render_template("build.html", error=error)

        # Save with the logged-in email
        save_build_to_db(session["my_build"], session["email"])
        return redirect(url_for("preview_build"))

    return render_template("build.html")

@app.route("/preview_build")
@login_required
def preview_build():
    my_build = session.get("my_build", None)
    return render_template("preview_build.html", my_build=my_build)

@app.route("/store")
def store():
    # store is visible without login
    return render_template("store.html", prebuilds=prebuilds)

# Replace your existing add_to_cart route with this one
@app.route("/api/add_to_cart/<int:pc_id>", methods=["POST"])
@login_required
def api_add_to_cart(pc_id):
    cart = session.get("cart", [])
    pc = next((p for p in prebuilds if p["id"] == pc_id), None)
    if not pc:
        return {"ok": False, "error": "product_not_found"}, 404
    cart.append({"id": pc["id"], "name": pc["name"], "price": pc["price"], "specs": pc.get("specs", [])})
    session["cart"] = cart
    counts = {}
    for it in cart:
        counts[it["id"]] = counts.get(it["id"], 0) + 1
    cart_total = sum(item["price"] for item in cart)
    return {"ok": True, "cart_count": len(cart), "counts": counts, "cart_total": cart_total}

# Fallback route used by non-JS forms and template POSTs.
# Put this in app.py near your other cart routes.
@app.route("/add_to_cart/<int:pc_id>", methods=["POST"])
def add_to_cart(pc_id):
    # If not logged in, send user to login page and redirect back to store after login
    if not session.get("logged_in"):
        return redirect(url_for("login", next=url_for("store")))

    # Add the product to the session cart (lightweight entry)
    cart = session.get("cart", [])
    pc = next((p for p in prebuilds if p["id"] == pc_id), None)
    if pc:
        cart.append({"id": pc["id"], "name": pc["name"], "price": pc["price"], "specs": pc.get("specs", [])})
        session["cart"] = cart

    # Redirect back to store so user can continue shopping
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
    idx = next((i for i, it in enumerate(cart) if it["id"] == pc_id), None)
    if idx is None:
        return {"ok": False, "error": "item_not_in_cart"}, 404
    cart.pop(idx)
    session["cart"] = cart
    counts = {}
    for it in cart:
        counts[it["id"]] = counts.get(it["id"], 0) + 1
    cart_total = sum(item["price"] for item in cart)
    return {"ok": True, "cart_count": len(cart), "counts": counts, "cart_total": cart_total}

@app.route("/shipping", methods=["GET", "POST"])
@login_required
def shipping():
    # If cart empty, send user to store
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

        # Save into session then proceed to checkout
        session["shipping"] = {"name": name, "address": address, "phone": phone}

        # ---- DEBUG & DB INSERT BLOCK START ----
        # This will log what is being stored and write the order into DB
        print(f"DEBUG: checkout called at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("DEBUG: session email:", session.get("email"))
        print("DEBUG: cart:", session.get("cart"))
        print("DEBUG: shipping:", session.get("shipping"))

        try:
            cart = session.get("cart", [])
            shipping_info = session.get("shipping", {})
            total = sum(item.get("price", 0) for item in cart)

            if cart and shipping_info:
                with get_db() as conn:
                    c = conn.cursor()
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
                    c.execute("""
                        INSERT INTO orders (email, name, address, phone, items_json, total)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        session.get("email"),
                        shipping_info.get("name"),
                        shipping_info.get("address"),
                        shipping_info.get("phone"),
                        json.dumps(cart),
                        total
                    ))
                    conn.commit()
                    print("DEBUG: order inserted, lastrowid:", c.lastrowid)
            else:
                print("DEBUG: no cart or no shipping - skipping DB insert")
        except Exception as e:
            print("ERROR saving order:", e)
            traceback.print_exc()
        # ---- DEBUG & DB INSERT BLOCK END ----

        # after saving, clear cart/shipping or redirect to preview/checkout
        return redirect(url_for("checkout"))

    # GET: render the shipping form
    return render_template("shipping.html", error=error)

@app.route("/cart")
@login_required
def cart():
    cart = session.get("cart", [])
    total = sum(item["price"] for item in cart)
    return render_template("cart.html", cart=cart, total=total)

@app.route("/checkout")
@login_required
def checkout():
    cart = session.get("cart", [])
    shipping = session.get("shipping", {})
    total = sum(item["price"] for item in cart)

    # Save order if we have shipping info
    if cart and shipping:
        with sqlite3.connect("pcstore.db", timeout=10) as conn:
            c = conn.cursor()
            c.execute("""
                INSERT INTO orders (email, name, address, phone, items_json, total)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                session.get("email"),
                shipping.get("name"),
                shipping.get("address"),
                shipping.get("phone"),
                json.dumps(cart),
                total
            ))
            conn.commit()

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

# ---------- Auth (email + password; safe hashing) ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    # If already logged in, go home or next
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
            # redirect new user to register with a hint
            return redirect(url_for("register", email=email))
        else:  # bad_password
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
        print("DEBUG register email raw:", repr(raw_email), "normalized:", repr(email))

        # Basic validation
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

@app.route("/admin")
@admin_required
def admin():
    create_tables()
    create_orders_table()

    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, email, brand, processor, motherboard, ram, ssd, gpu, psu, cooling, aio
            FROM builds ORDER BY id DESC
        """)
        builds = c.fetchall()

    with get_db() as conn:
        c = conn.cursor()
        c.execute("""
            SELECT id, email, name, address, phone, items_json, total
            FROM orders ORDER BY id DESC
        """)
        orders = c.fetchall()

    def rowdict(row): return {k: row[k] for k in row.keys()}
    import json
    builds_list = [rowdict(r) for r in builds]
    orders_list = []
    for r in orders:
        d = rowdict(r)
        try: d["items"] = json.loads(d.get("items_json") or "[]")
        except: d["items"] = []
        orders_list.append(d)

    return render_template("admin.html", builds=builds_list, orders=orders_list)

@app.route("/admin/initdb")
@admin_required
def admin_initdb():
    # Force-create tables and show what exists now
    create_tables()
    create_orders_table()
    info = list_tables_and_db_path()
    return f"<pre>DB Path: {info['db_path']}\nTables: {info['tables']}</pre>"

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

if __name__ == "__main__":
    print("🚀 Flask app started (email/password auth).")
    app.run(debug=True)
