from flask import Flask, render_template, session, redirect, url_for, request
import sqlite3
import hashlib

app = Flask(__name__)
app.secret_key = "mysecretkey"  # Needed for sessions

# ✅ Helper function to save a build to SQLite
def save_build_to_db(build):
    print("💾 DEBUG: Connecting to database...")
    conn = sqlite3.connect("pcstore.db")
    c = conn.cursor()
    # Create table if it doesn't exist
    c.execute("""
        CREATE TABLE IF NOT EXISTS builds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    print("💾 DEBUG: Inserting build:", build)
    c.execute("""
        INSERT INTO builds (brand, processor, motherboard, ram, ssd, gpu, psu, cooling, aio)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        build["brand"], build["processor"], build["motherboard"],
        build["ram"], build["ssd"], build["gpu"],
        build["psu"], build["cooling"], build["aio"]
    ))
    conn.commit()
    conn.close()
    print("💾 DEBUG: Build successfully saved!")


# ✅ User auth helpers
def create_users_table():
    conn = sqlite3.connect("pcstore.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

# Call this once at startup
create_users_table()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def register_user(username, password):
    conn = sqlite3.connect("pcstore.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def validate_login(username, password):
    conn = sqlite3.connect("pcstore.db")
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row and row[0] == hash_password(password):
        return True
    return False


# ---- Prebuild PC list (unchanged) ----
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


# ---- Routes ----
@app.route("/")
def home():
    return render_template("home.html", prebuilds=prebuilds)

@app.route("/build", methods=["GET", "POST"])
def build():
    if request.method == "POST":
        session["my_build"] = {
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
        print("✅ DEBUG: Build received:", session["my_build"])

        # Save to database
        save_build_to_db(session["my_build"])
        print("✅ DEBUG: Build saved to database!")

        return redirect(url_for("preview_build"))

    return render_template("build.html")

@app.route("/preview_build")
def preview_build():
    my_build = session.get("my_build", None)
    return render_template("preview_build.html", my_build=my_build)

@app.route("/store")
def store():
    return render_template("store.html", prebuilds=prebuilds)

@app.route("/add_to_cart/<int:pc_id>")
def add_to_cart(pc_id):
    cart = session.get("cart", [])
    for pc in prebuilds:
        if pc["id"] == pc_id:
            cart.append(pc)
            break
    session["cart"] = cart
    return redirect(url_for("cart"))

@app.route("/remove_from_cart/<int:index>")
def remove_from_cart(index):
    cart = session.get("cart", [])
    if 0 <= index < len(cart):
        cart.pop(index)
    session["cart"] = cart
    return redirect(url_for("cart"))

@app.route("/cart")
def cart():
    cart = session.get("cart", [])
    total = sum(item["price"] for item in cart)
    return render_template("cart.html", cart=cart, total=total)

@app.route("/checkout")
def checkout():
    cart = session.get("cart", [])
    total = sum(item["price"] for item in cart)
    session["cart"] = []  # clear cart after checkout
    return render_template("checkout.html", total=total)

# ✅ View all submitted builds (admin only)
@app.route("/submissions")
def submissions():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    conn = sqlite3.connect("pcstore.db")
    c = conn.cursor()
    c.execute("SELECT * FROM builds")
    builds = c.fetchall()
    conn.close()
    return render_template("submissions.html", builds=builds)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if validate_login(username, password):
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("submissions"))
        else:
            error = "Invalid username or password"
    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if register_user(username, password):
            success = "✅ Account created! You can now log in."
        else:
            error = "❌ Username already exists."
    return render_template("register.html", error=error, success=success)

@app.route("/logout")
def logout():
    session.pop("logged_in", None)
    session.pop("username", None)
    return redirect(url_for("home"))

if __name__ == "__main__":
    print("🚀 Flask app has started!")
    app.run(debug=True)
