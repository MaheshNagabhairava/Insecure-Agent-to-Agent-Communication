from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, g
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import xml.etree.ElementTree as ET
import re
from functools import wraps
import time
import hashlib
import secrets
import json
import logging
from datetime import datetime, timezone

app = Flask(__name__, static_folder='static')
app.secret_key = 'your-secret-key-change-in-production'

# Configure session cookies to not be http-only (for testing purposes)
app.config['SESSION_COOKIE_HTTPONLY'] = False

# Rate limiting storage
rate_limit_storage = {}


# ============== SIEM LOGGING CONFIGURATION ==============
# Create logs directory if it doesn't exist
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
os.makedirs(log_dir, exist_ok=True)

# Configure SIEM logger
siem_logger = logging.getLogger('siem')
siem_logger.setLevel(logging.INFO)
siem_handler = logging.FileHandler(os.path.join(log_dir, 'app_requests.log'), encoding='utf-8')
siem_handler.setFormatter(logging.Formatter('%(message)s'))
siem_logger.addHandler(siem_handler)
siem_logger.propagate = False

@app.before_request
def log_request_start():
    """Capture request details before processing"""
    g.request_start_time = time.time()
    # Store request body for logging (must be read before processing)
    if request.method in ['POST', 'PUT', 'PATCH']:
        if request.content_type and 'application/json' in request.content_type:
            try:
                g.request_body = request.get_json(silent=True) or {}
            except:
                g.request_body = {}
        elif request.form:
            g.request_body = dict(request.form)
        else:
            g.request_body = {}
    else:
        g.request_body = dict(request.args) if request.args else {}

@app.after_request
def log_request_complete(response):
    """Log complete request details after processing"""
    # Skip logging for static files
    if request.path.startswith('/static'):
        return response
    
    log_entry = {
        "timestamp": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z',
        "path": request.path,
        "url": request.url,
        "client_ip": request.remote_addr,
        "request_body": {k: v for k, v in getattr(g, 'request_body', {}).items() if k.lower() != 'password'},
        "response_status": response.status_code,
        "username": session.get('username', None)
    }
    
    siem_logger.info(json.dumps(log_entry))
    return response
# ============== END SIEM LOGGING ==============


# ============== IP BLOCKLIST CONFIGURATION ==============
# Path to the IP blocklist file (shared with agents)
BLOCKLIST_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 
    '..', 
    'agents', 
    'blocked_ips.json'
)


def is_ip_blocked(ip_address: str) -> tuple:
    """
    Check if an IP address is blocked.
    Returns (is_blocked, block_info) tuple.
    """
    if not os.path.exists(BLOCKLIST_PATH):
        return False, None
    
    try:
        with open(BLOCKLIST_PATH, 'r', encoding='utf-8') as f:
            blocklist = json.load(f)
        
        if ip_address in blocklist:
            block_info = blocklist[ip_address]
            expires_at = datetime.fromisoformat(block_info['expires_at'])
            
            # Check if block has expired
            if expires_at > datetime.utcnow():
                return True, block_info
    except Exception as e:
        app.logger.error(f"Error checking IP blocklist: {e}")
    
    return False, None


@app.before_request
def check_ip_blocklist():
    """Check if client IP is blocked before processing request."""
    # Skip for API endpoints (allow session invalidation even for blocked IPs)
    if request.path.startswith('/api/'):
        return None
    
    client_ip = request.remote_addr
    is_blocked, block_info = is_ip_blocked(client_ip)
    
    if is_blocked:
        expires_at = block_info.get('expires_at', 'unknown')
        return jsonify({
            'error': 'Access Denied',
            'message': f'Your IP address has been blocked due to suspicious activity.',
            'blocked_until': expires_at
        }), 403
    
    return None


@app.before_request
def check_session_validity():
    """
    Check if the user's session has been invalidated server-side.
    Runs on every request for logged-in users.
    """
    # Skip for static files and public endpoints
    if request.path.startswith('/static') or request.endpoint in ['login', 'logout', 'index', 'register']:
        return None
        
    if 'user_id' in session and 'username' in session:
        try:
            conn = sqlite3.connect('shopping.db')
            cursor = conn.cursor()
            cursor.execute('SELECT invalidated_at FROM users WHERE id = ?', (session['user_id'],))
            result = cursor.fetchone()
            conn.close()
            
            if result:
                invalidated_at = result[0]
                login_time = session.get('login_time', 0)
                
                # If user was invalidated AFTER they logged in, kill the session
                if invalidated_at > login_time:
                    session.clear()
                    flash('Your session has been invalidated by security policy. Please log in again.', 'error')
                    return redirect(url_for('login'))
        except Exception as e:
            app.logger.error(f"Error checking session validity: {e}")
            
    return None


@app.route('/api/invalidate-session', methods=['POST'])
def invalidate_session_api():
    """
    API endpoint to invalidate a user's session.
    Called by the Execution Agent.
    
    SECURITY NOTE: In production, this should require authentication.
    """
    data = request.get_json()
    username = data.get('username')
    
    if not username:
        return jsonify({'error': 'Username required'}), 400
    
    # Log the invalidation request
    app.logger.info(f"Session invalidation requested for user: {username}")
    
    try:
        conn = sqlite3.connect('shopping.db')
        cursor = conn.cursor()
        
        # Set invalidated_at to current timestamp
        current_time = time.time()
        cursor.execute('UPDATE users SET invalidated_at = ? WHERE username = ?', (current_time, username))
        conn.commit()
        rows_affected = cursor.rowcount
        conn.close()
        
        if rows_affected > 0:
            return jsonify({
                'status': 'success',
                'message': f'Session invalidated for {username}',
                'timestamp': current_time
            })
        else:
            return jsonify({
                'error': 'User not found'
            }), 404
            
    except Exception as e:
        app.logger.error(f"Database error during session invalidation: {e}")
        return jsonify({'error': str(e)}), 500
# ============== END IP BLOCKLIST ==============


# Context processor to inject user login status into all templates
@app.context_processor
def inject_user_status():
    return dict(user_logged_in='user_id' in session)

def init_db():
    """Initialize the database with tables"""
    conn = sqlite3.connect('shopping.db')
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            wallet_balance REAL DEFAULT 30000.00,
            invalidated_at REAL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Add wallet_balance column to existing users table if it doesn't exist
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN wallet_balance REAL DEFAULT 30000.00')
        # Update existing users with default wallet balance
        cursor.execute('UPDATE users SET wallet_balance = 30000.00 WHERE wallet_balance IS NULL')
    except sqlite3.OperationalError:
        pass
        
    # Add invalidated_at column to existing users table if it doesn't exist
    try:
        cursor.execute('ALTER TABLE users ADD COLUMN invalidated_at REAL DEFAULT 0')
    except sqlite3.OperationalError:
        pass
    
    # Products table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            price REAL NOT NULL,
            image_url TEXT,
            stock INTEGER DEFAULT 100
        )
    ''')
    
    # Orders table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL,
            total_price REAL NOT NULL,
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'pending',
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')
    
    # User profiles table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER UNIQUE NOT NULL,
            bio TEXT,
            location TEXT,
            website TEXT,
            avatar_url TEXT,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Product reviews table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS product_reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
            review_text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id)
        )
    ''')
    
    # Shopping cart table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS cart_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            product_id INTEGER NOT NULL,
            quantity INTEGER NOT NULL DEFAULT 1,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (product_id) REFERENCES products (id),
            UNIQUE(user_id, product_id)
        )
    ''')
    
    # Insert sample products (always update to ensure latest images)
    cursor.execute('DELETE FROM products')  # Clear existing products to get latest images
    
    sample_products = [
            ('iPhone 15 Pro', 'Latest iPhone with advanced camera system and titanium design', 999.99, '/static/images/iphone-15-pro.jpg'),
            ('MacBook Air M2', 'Ultra-thin laptop with M2 chip and all-day battery life', 1199.99, '/static/images/macbook-air-m2.jpg'),
            ('AirPods Pro', 'Wireless earbuds with active noise cancellation and spatial audio', 249.99, '/static/images/airpods-pro.jpg'),
            ('Apple Watch Series 9', 'Smartwatch with advanced health monitoring and fitness tracking', 399.99, '/static/images/apple-watch-series-9.jpg'),
            ('iPad Pro', 'Professional tablet with M2 chip perfect for creative work', 799.99, '/static/images/ipad-pro.jpg')
    ]
    
    for product in sample_products:
        cursor.execute('''
            INSERT INTO products (name, description, price, image_url)
            VALUES (?, ?, ?, ?)
        ''', product)
    
    # Insert sample reviews (always update)
    cursor.execute('DELETE FROM product_reviews')
    cursor.execute('DELETE FROM users WHERE username = ?', ('demo_user',))
    
    # Create a sample user for reviews
    cursor.execute('''
        INSERT OR IGNORE INTO users (username, email, password_hash, wallet_balance)
        VALUES (?, ?, ?, ?)
    ''', ('demo_user', 'demo@example.com', generate_password_hash('demo123'), 30000.00))
    
    cursor.execute('SELECT id FROM users WHERE username = ?', ('demo_user',))
    demo_user_id = cursor.fetchone()[0]
    
    sample_reviews = [
        (demo_user_id, 1, 5, 'Amazing phone! The camera quality is outstanding and the performance is incredible.'),
        (demo_user_id, 2, 4, 'Great laptop for work and entertainment. Battery life could be better though.'),
        (demo_user_id, 3, 5, 'Perfect sound quality and the noise cancellation works like magic!'),
        (demo_user_id, 4, 4, 'Love the health monitoring features. Sleep tracking is very accurate.'),
        (demo_user_id, 5, 5, 'Perfect for graphic design work. The display is absolutely stunning.')
    ]
    
    for review in sample_reviews:
        cursor.execute('''
            INSERT INTO product_reviews (user_id, product_id, rating, review_text)
            VALUES (?, ?, ?, ?)
        ''', review)
    
    conn.commit()
    conn.close()

def login_required(f):
    """Decorator to require login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(max_requests=5, window=60):
    """Rate limiting decorator"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            current_time = time.time()
            
            # Clean old entries
            if client_ip in rate_limit_storage:
                rate_limit_storage[client_ip] = [
                    timestamp for timestamp in rate_limit_storage[client_ip]
                    if current_time - timestamp < window
                ]
            else:
                rate_limit_storage[client_ip] = []
            
            # Check if limit exceeded
            if len(rate_limit_storage[client_ip]) >= max_requests:
                flash('Too many requests. Please try again later.', 'error')
                return render_template('login.html'), 429
            
            # Add current request
            rate_limit_storage[client_ip].append(current_time)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


@app.route('/')
def index():
    """Home page with product listing"""
    conn = sqlite3.connect('shopping.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products')
    products = cursor.fetchall()
    conn.close()
    
    return render_template('index.html', products=products)

@app.route('/register', methods=['GET', 'POST'])
@rate_limit(max_requests=10, window=300)  # 10 attempts per 5 minutes
def register():
    """User registration"""
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        if not username or not email or not password:
            flash('All fields are required.', 'error')
            return render_template('register.html')
        
        conn = sqlite3.connect('shopping.db')
        cursor = conn.cursor()
        
        try:
            password_hash = generate_password_hash(password)
            cursor.execute('''
                INSERT INTO users (username, email, password_hash, wallet_balance)
                VALUES (?, ?, ?, ?)
            ''', (username, email, password_hash, 30000.00))
            conn.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'error')
            return render_template('register.html')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
@rate_limit(max_requests=10, window=60)  # 10 attempts per minute
def login():
    """User login"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('shopping.db')
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, password_hash, COALESCE(is_blocked, 0) FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            # Check if account is blocked
            is_blocked = user[3]
            if is_blocked == 1:
                flash('Your account has been blocked due to security concerns. Please contact support.', 'error')
                return render_template('login.html')
            
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['login_time'] = time.time()  # Store login timestamp for invalidation checks
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.', 'error')
    
    return render_template('login.html')


@app.route('/logout')
def logout():
    """User logout"""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    """Product detail page"""
    conn = sqlite3.connect('shopping.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    conn.close()
    
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('index'))
    
    return render_template('product_detail.html', product=product)

@app.route('/add_to_cart', methods=['POST'])
@login_required
def add_to_cart():
    """Add product to cart"""
    product_id = request.form['product_id']
    quantity = int(request.form['quantity'])
    
    conn = sqlite3.connect('shopping.db')
    cursor = conn.cursor()
    
    # Check if product exists
    cursor.execute('SELECT id FROM products WHERE id = ?', (product_id,))
    if not cursor.fetchone():
        flash('Product not found.', 'error')
        conn.close()
        return redirect(url_for('index'))
    
    # Check if item already in cart
    cursor.execute('SELECT id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?', 
                   (session['user_id'], product_id))
    existing_item = cursor.fetchone()
    
    if existing_item:
        # Update quantity
        new_quantity = existing_item[1] + quantity
        cursor.execute('UPDATE cart_items SET quantity = ? WHERE id = ?', 
                       (new_quantity, existing_item[0]))
    else:
        # Add new item to cart
        cursor.execute('''
            INSERT INTO cart_items (user_id, product_id, quantity)
            VALUES (?, ?, ?)
        ''', (session['user_id'], product_id, quantity))
    
    conn.commit()
    conn.close()
    
    flash('Product added to cart!', 'success')
    return redirect(url_for('cart'))

@app.route('/cart')
@login_required
def cart():
    """View shopping cart"""
    conn = sqlite3.connect('shopping.db')
    cursor = conn.cursor()
    
    # Get user wallet balance
    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (session['user_id'],))
    wallet_balance = cursor.fetchone()[0]
    
    # Get cart items with product details
    cursor.execute('''
        SELECT c.id, c.user_id, c.product_id, c.quantity, c.added_at, p.name, p.price, p.image_url, p.stock
        FROM cart_items c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
        ORDER BY c.added_at DESC
    ''', (session['user_id'],))
    cart_items = cursor.fetchall()
    
    # Calculate totals
    total_items = sum(item[3] for item in cart_items)  # item[3] = quantity
    total_amount = sum(item[3] * item[6] for item in cart_items)  # item[3] = quantity, item[6] = price
    
    conn.close()
    
    return render_template('cart.html', cart_items=cart_items, wallet_balance=wallet_balance, 
                         total_items=total_items, total_amount=total_amount)

@app.route('/update_cart', methods=['POST'])
@login_required
def update_cart():
    """Update cart item quantity"""
    cart_item_id = request.form['cart_item_id']
    quantity = int(request.form['quantity'])
    
    if quantity <= 0:
        # Remove item from cart
        conn = sqlite3.connect('shopping.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM cart_items WHERE id = ? AND user_id = ?', 
                       (cart_item_id, session['user_id']))
        conn.commit()
        conn.close()
        flash('Item removed from cart.', 'info')
    else:
        # Update quantity
        conn = sqlite3.connect('shopping.db')
        cursor = conn.cursor()
        cursor.execute('UPDATE cart_items SET quantity = ? WHERE id = ? AND user_id = ?', 
                       (quantity, cart_item_id, session['user_id']))
        conn.commit()
        conn.close()
        flash('Cart updated.', 'success')
    
    return redirect(url_for('cart'))

@app.route('/place_order', methods=['POST'])
@login_required
def place_order():
    """Place order from cart - VULNERABLE TO BLIND SQL INJECTION"""
    conn = sqlite3.connect('shopping.db')
    cursor = conn.cursor()
    
    # Get user wallet balance
    cursor.execute('SELECT wallet_balance FROM users WHERE id = ?', (session['user_id'],))
    wallet_balance = cursor.fetchone()[0]
    
    # Get cart items
    cursor.execute('''
        SELECT c.id, c.user_id, c.product_id, c.quantity, c.added_at, p.name, p.price, p.stock
        FROM cart_items c
        JOIN products p ON c.product_id = p.id
        WHERE c.user_id = ?
    ''', (session['user_id'],))
    cart_items = cursor.fetchall()
    
    if not cart_items:
        flash('Your cart is empty.', 'error')
        conn.close()
        return redirect(url_for('cart'))
    
    # Calculate total
    total_amount = sum(item[3] * item[6] for item in cart_items)  # item[3] = quantity, item[6] = price
    
    # Check wallet balance
    if wallet_balance < total_amount:
        flash(f'Insufficient funds. You have ${wallet_balance:.2f}, need ${total_amount:.2f}', 'error')
        conn.close()
        return redirect(url_for('cart'))
    
    # VULNERABILITY: Blind SQL injection - properly vulnerable to time-based and boolean-based attacks
    # This is intentionally vulnerable for security testing
    import time
    
    # Get user input from form
    user_input = request.form.get('special_note', '1=1')
    
    try:
        # Time-based blind SQL injection for SQLite
        # SQLite doesn't have SLEEP, so we simulate it with Python
        if 'SLEEP(' in user_input.upper() or 'WAITFOR' in user_input.upper() or 'DELAY' in user_input.upper():
            import re
            # Extract sleep duration from input - NO CAP, use exact time requested
            sleep_match = re.search(r'SLEEP\s*\(\s*(\d+)\s*\)', user_input.upper())
            if sleep_match:
                sleep_time = int(sleep_match.group(1))  # Use exact time, no cap
                time.sleep(sleep_time)
            else:
                time.sleep(3)  # Default delay
        
        # Boolean-based blind SQL injection (only if no SLEEP detected)
        elif 'SLEEP(' not in user_input.upper():
            # Test with: 1=1 (true), 1=2 (false), username='admin', etc.
            # Use a more realistic query that actually executes the injection
            query = f"SELECT * FROM users WHERE id = {session['user_id']} AND ({user_input})"
            
            cursor.execute(query)
            result = cursor.fetchone()
            
            # Boolean-based response - create different behavior based on result
            if result:
                # True condition - query returned data, add delay to simulate processing
                time.sleep(1.0)  # Longer delay for true conditions
            else:
                # False condition - query returned no data, shorter delay
                time.sleep(0.2)  # Shorter delay for false conditions
            
    except Exception as e:
        # Hide SQL errors to make it truly blind
        # But still add a delay to indicate error occurred
        time.sleep(0.5)
        pass
    
    # Process orders
    for item in cart_items:
        cursor.execute('''
            INSERT INTO orders (user_id, product_id, quantity, total_price)
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], item[2], item[3], item[3] * item[6]))  # item[2] = product_id, item[3] = quantity, item[6] = price
    
    # Update wallet balance
    cursor.execute('UPDATE users SET wallet_balance = wallet_balance - ? WHERE id = ?', 
                   (total_amount, session['user_id']))
    
    # Clear cart
    cursor.execute('DELETE FROM cart_items WHERE user_id = ?', (session['user_id'],))
    
    conn.commit()
    conn.close()
    
    flash(f'Order placed successfully! Total: ${total_amount:.2f}', 'success')
    return redirect(url_for('my_orders'))

@app.route('/my_orders')
@login_required
def my_orders():
    """View user's orders"""
    conn = sqlite3.connect('shopping.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT o.*, p.name, p.price
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE o.user_id = ?
        ORDER BY o.order_date DESC
    ''', (session['user_id'],))
    orders = cursor.fetchall()
    conn.close()
    
    return render_template('my_orders.html', orders=orders)

@app.route('/search')
@login_required
def search():
    """Search functionality - SECURE IMPLEMENTATION"""
    query = request.args.get('q', '')
    
    if query:
        # Secure search implementation
        conn = sqlite3.connect('shopping.db')
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM products 
            WHERE name LIKE ? OR description LIKE ?
        ''', (f'%{query}%', f'%{query}%'))
        results = cursor.fetchall()
        conn.close()
    else:
        results = []
    
    return render_template('search.html', query=query, results=results)

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    conn = sqlite3.connect('shopping.db')
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.username, u.email, u.created_at, u.wallet_balance, p.bio, p.location, p.website, p.avatar_url
        FROM users u
        LEFT JOIN user_profiles p ON u.id = p.user_id
        WHERE u.id = ?
    ''', (session['user_id'],))
    user_data = cursor.fetchone()
    conn.close()
    
    return render_template('profile.html', user=user_data)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile"""
    if request.method == 'POST':
        bio = request.form['bio']
        location = request.form['location']
        website = request.form['website']
        
        conn = sqlite3.connect('shopping.db')
        cursor = conn.cursor()
        
        # Insert or update profile
        cursor.execute('''
            INSERT OR REPLACE INTO user_profiles (user_id, bio, location, website)
            VALUES (?, ?, ?, ?)
        ''', (session['user_id'], bio, location, website))
        
        conn.commit()
        conn.close()
        
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html')

@app.route('/product/<int:product_id>/reviews')
def product_reviews(product_id):
    """View product reviews"""
    conn = sqlite3.connect('shopping.db')
    cursor = conn.cursor()
    
    # Get product info
    cursor.execute('SELECT * FROM products WHERE id = ?', (product_id,))
    product = cursor.fetchone()
    
    if not product:
        flash('Product not found.', 'error')
        return redirect(url_for('index'))
    
    # Get reviews with user info
    cursor.execute('''
        SELECT r.*, u.username, up.avatar_url
        FROM product_reviews r
        JOIN users u ON r.user_id = u.id
        LEFT JOIN user_profiles up ON u.id = up.user_id
        WHERE r.product_id = ?
        ORDER BY r.created_at DESC
    ''', (product_id,))
    reviews = cursor.fetchall()
    
    conn.close()
    
    return render_template('product_reviews.html', product=product, reviews=reviews)

@app.route('/submit_review', methods=['POST'])
@login_required
def submit_review():
    """Submit product review - VULNERABLE TO REFLECTED XSS"""
    product_id = request.form['product_id']
    rating = int(request.form['rating'])
    review_text = request.form['review_text']
    
    # VULNERABILITY: Reflected XSS in review text
    # This is intentionally vulnerable for security testing - very realistic scenario
    # User input is directly stored and displayed without sanitization
    
    conn = sqlite3.connect('shopping.db')
    cursor = conn.cursor()
    
    # Check if user already reviewed this product
    cursor.execute('''
        SELECT id FROM product_reviews 
        WHERE user_id = ? AND product_id = ?
    ''', (session['user_id'], product_id))
    
    if cursor.fetchone():
        flash('You have already reviewed this product.', 'error')
        conn.close()
        return redirect(url_for('product_reviews', product_id=product_id))
    
    # Insert review
    cursor.execute('''
        INSERT INTO product_reviews (user_id, product_id, rating, review_text)
        VALUES (?, ?, ?, ?)
    ''', (session['user_id'], product_id, rating, review_text))
    
    conn.commit()
    conn.close()
    
    flash('Review submitted successfully!', 'success')
    return redirect(url_for('product_reviews', product_id=product_id))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
