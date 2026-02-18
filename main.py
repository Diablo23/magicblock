"""
Magicblob API with Twitter OAuth + PostgreSQL Database
"""

from flask import Flask, request, jsonify, redirect, session
from flask_cors import CORS
import requests
import re
import secrets
import hashlib
import base64
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import os
from urllib.parse import urlencode
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
CORS(app, supports_credentials=True)

# ============================================================
# CONFIG FROM ENVIRONMENT VARIABLES
# ============================================================
TWITTER_CLIENT_ID = os.environ.get("TWITTER_CLIENT_ID", "")
TWITTER_CLIENT_SECRET = os.environ.get("TWITTER_CLIENT_SECRET", "")
TWITTER_REDIRECT_URI = os.environ.get("TWITTER_REDIRECT_URI", "https://api.bulkgram.com/callback")
FRONTEND_URL = os.environ.get("FRONTEND_URL", "https://bulkgram.com")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# ============================================================
# ADMIN USERS
# ============================================================
ADMIN_USERNAMES = ["qurool13"]

def is_admin(user):
    """Check if user is an admin"""
    if not user:
        return False
    return user.get("username", "").lower() in [u.lower() for u in ADMIN_USERNAMES]

def get_db():
    """Get database connection"""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

def get_cursor(conn):
    """Get a cursor that returns dict-like rows"""
    return conn.cursor(cursor_factory=RealDictCursor)

def init_db():
    """Initialize database tables"""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            name TEXT,
            pfp TEXT,
            bio TEXT DEFAULT '',
            access_token TEXT,
            votes_today INTEGER DEFAULT 0,
            ratings_today INTEGER DEFAULT 0,
            last_vote_reset TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Posts table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS posts (
            id SERIAL PRIMARY KEY,
            url TEXT NOT NULL,
            image TEXT,
            text TEXT,
            author TEXT,
            author_pfp TEXT,
            categories TEXT,
            likes INTEGER DEFAULT 0,
            dislikes INTEGER DEFAULT 0,
            slop_count INTEGER DEFAULT 0,
            user_id TEXT,
            user_username TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Votes table (track who voted on what)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS votes (
            id SERIAL PRIMARY KEY,
            post_id INTEGER NOT NULL,
            user_id TEXT NOT NULL,
            vote_type TEXT NOT NULL,
            is_rating INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(post_id, user_id)
        )
    ''')
    
    # AI Slop reports table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS slop_reports (
            id SERIAL PRIMARY KEY,
            post_id INTEGER NOT NULL,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(post_id, user_id)
        )
    ''')
    
    # Follows table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS follows (
            id SERIAL PRIMARY KEY,
            follower_id TEXT NOT NULL,
            following_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(follower_id, following_id)
        )
    ''')
    
    # Sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Weekly Leaderboard table - stores top 3 posts per category per week
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS weekly_leaderboard (
            id SERIAL PRIMARY KEY,
            week_start TEXT NOT NULL,
            week_end TEXT NOT NULL,
            category TEXT NOT NULL,
            rank INTEGER NOT NULL,
            post_id INTEGER NOT NULL,
            post_url TEXT,
            post_image TEXT,
            post_text TEXT,
            user_id TEXT,
            user_username TEXT,
            user_name TEXT,
            user_pfp TEXT,
            likes INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(week_start, category, rank)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized")

# ============================================================
# HELPER FUNCTIONS
# ============================================================

# Voting limits
DAILY_VOTE_LIMIT = 20
REQUIRED_RATINGS = 3

def get_today():
    """Get today's date as string (UTC)"""
    return datetime.utcnow().strftime('%Y-%m-%d')

def get_current_week_bounds():
    """Get Monday 00:00 and Sunday 23:59 of current week (UTC)"""
    today = datetime.utcnow()
    # Monday of current week
    monday = today - timedelta(days=today.weekday())
    monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
    # Sunday of current week
    sunday = monday + timedelta(days=6, hours=23, minutes=59, seconds=59)
    return monday, sunday

def get_week_bounds_for_date(date_str):
    """Get Monday and Sunday for a given date"""
    date = datetime.strptime(date_str, '%Y-%m-%d')
    monday = date - timedelta(days=date.weekday())
    monday = monday.replace(hour=0, minute=0, second=0, microsecond=0)
    sunday = monday + timedelta(days=6, hours=23, minutes=59, seconds=59)
    return monday, sunday

def format_week_label(monday, sunday):
    """Format week as 'DD.MM - DD.MM'"""
    return f"{monday.strftime('%d.%m')} - {sunday.strftime('%d.%m')}"

def generate_code_verifier():
    return secrets.token_urlsafe(32)

def generate_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode()

def is_twitter_url(url):
    return "twitter.com" in url or "x.com" in url

def extract_tweet_id(url):
    match = re.search(r'/status/(\d+)', url)
    return match.group(1) if match else None

def extract_username(url):
    match = re.search(r'(?:twitter\.com|x\.com)/(\w+)/status', url)
    return f"@{match.group(1)}" if match else None

def truncate_text(text, max_length=50):
    if not text:
        return ""
    text = re.sub(r'https?://\S+', '', text)
    text = re.sub(r't\.co/\S+', '', text)
    text = re.sub(r'\s+', ' ', text.strip())
    if not text:
        return ""
    if len(text) <= max_length:
        return text
    return text[:max_length].rstrip() + "..."

def check_and_reset_daily_votes(user_id):
    """Check if user's daily votes need to be reset (new day)"""
    conn = get_db()
    cursor = get_cursor(conn)
    
    cursor.execute('SELECT last_vote_reset, votes_today, ratings_today FROM users WHERE id = %s', (user_id,))
    row = cursor.fetchone()
    
    today = get_today()
    
    if row and row['last_vote_reset'] != today:
        # New day - reset counters
        cursor.execute('''
            UPDATE users SET votes_today = 0, ratings_today = 0, last_vote_reset = %s
            WHERE id = %s
        ''', (today, user_id))
        conn.commit()
        conn.close()
        return {'votes_today': 0, 'ratings_today': 0}
    
    conn.close()
    return {'votes_today': row['votes_today'] if row else 0, 'ratings_today': row['ratings_today'] if row else 0}

def get_user_vote_status(user_id):
    """Get user's voting status for today"""
    daily = check_and_reset_daily_votes(user_id)
    
    can_vote = daily['ratings_today'] >= REQUIRED_RATINGS
    votes_remaining = max(0, DAILY_VOTE_LIMIT - daily['votes_today']) if can_vote else 0
    ratings_needed = max(0, REQUIRED_RATINGS - daily['ratings_today'])
    
    return {
        'can_vote': can_vote,
        'votes_remaining': votes_remaining,
        'votes_today': daily['votes_today'],
        'ratings_today': daily['ratings_today'],
        'ratings_needed': ratings_needed,
        'daily_limit': DAILY_VOTE_LIMIT,
        'required_ratings': REQUIRED_RATINGS
    }

def get_user_from_token(token):
    """Get user from session token"""
    if not token:
        return None
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('''
        SELECT u.* FROM users u
        JOIN sessions s ON u.id = s.user_id
        WHERE s.token = %s
    ''', (token,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def post_to_dict(row):
    """Convert post row to dictionary"""
    post = dict(row)
    # Parse categories from JSON string
    if post.get('categories'):
        try:
            post['categories'] = json.loads(post['categories'])
        except:
            post['categories'] = []
    else:
        post['categories'] = []
    
    # Ensure created_at is in ISO format with Z suffix for UTC
    if post.get('created_at'):
        # Add Z suffix if not present to indicate UTC
        created_at = str(post['created_at'])
        if not created_at.endswith('Z') and '+' not in created_at:
            post['created_at'] = created_at.replace(' ', 'T') + 'Z'
    
    return post

# ============================================================
# TWEET PREVIEW FUNCTIONS
# ============================================================

def fetch_via_vxtwitter(url):
    """Fetch via vxtwitter.com API"""
    try:
        tweet_id = extract_tweet_id(url)
        api_url = f"https://api.vxtwitter.com/Twitter/status/{tweet_id}"
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            print(f"vxtwitter raw data: {data}")
            
            image = None
            if data.get("media_extended") and len(data["media_extended"]) > 0:
                for media in data["media_extended"]:
                    if media.get("type") == "image" and not image:
                        image = media.get("url")
                    elif media.get("type") == "video" and not image:
                        image = media.get("thumbnail_url")
            
            if not image and data.get("article"):
                image = data["article"].get("image")
            
            text = data.get("text", "")
            text_clean = truncate_text(text)
            
            if not text_clean:
                if data.get("article"):
                    text_clean = truncate_text(data["article"].get("title", ""))
                if not text_clean and data.get("quote"):
                    text_clean = truncate_text(f"QT: {data['quote'].get('text', '')}")
                if not text_clean and data.get("card"):
                    text_clean = truncate_text(data["card"].get("title", ""))
            
            return {
                "image": image,
                "text": text_clean,
                "author": f"@{data.get('user_screen_name', '')}" if data.get("user_screen_name") else extract_username(url),
                "author_pfp": data.get("user_profile_image_url", "").replace("_normal", "_400x400"),
                "source": "vxtwitter"
            }
    except Exception as e:
        print(f"vxtwitter error: {e}")
    return None

def fetch_via_fxtwitter(url):
    """Fetch via fxtwitter.com"""
    try:
        tweet_id = extract_tweet_id(url)
        fx_url = f"https://fxtwitter.com/i/status/{tweet_id}"
        headers = {"User-Agent": "Mozilla/5.0 (compatible; Discordbot/2.0)"}
        response = requests.get(fx_url, headers=headers, timeout=10)
        html = response.text
        
        image = None
        image_match = re.search(r'<meta[^>]*property=["\']og:image["\'][^>]*content=["\']([^"\']+)["\']', html)
        if not image_match:
            image_match = re.search(r'<meta[^>]*content=["\']([^"\']+)["\'][^>]*property=["\']og:image["\']', html)
        if image_match:
            image = image_match.group(1)
        
        title = None
        title_match = re.search(r'<meta[^>]*property=["\']og:title["\'][^>]*content=["\']([^"\']+)["\']', html)
        if title_match:
            title = title_match.group(1)
        
        text = None
        desc_match = re.search(r'<meta[^>]*property=["\']og:description["\'][^>]*content=["\']([^"\']+)["\']', html)
        if desc_match:
            text = desc_match.group(1)
        
        text_clean = truncate_text(text)
        if not text_clean and title:
            clean_title = re.sub(r'^.*?\s+on\s+X:\s*', '', title)
            text_clean = truncate_text(clean_title)
        
        if image or text_clean:
            return {
                "image": image,
                "text": text_clean,
                "author": extract_username(url),
                "author_pfp": None,
                "source": "fxtwitter"
            }
    except Exception as e:
        print(f"fxtwitter error: {e}")
    return None

def fetch_via_oembed(url):
    """Fetch via Twitter's oEmbed"""
    try:
        oembed_url = f"https://publish.twitter.com/oembed?url={url}&omit_script=true"
        response = requests.get(oembed_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            text = None
            if data.get("html"):
                match = re.search(r'<p[^>]*>(.*?)</p>', data["html"], re.DOTALL)
                if match:
                    text = re.sub(r'<[^>]+>', '', match.group(1))
                    text = text.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
            
            return {
                "image": None,
                "text": truncate_text(text),
                "author": f"@{data.get('author_name', '')}" if data.get("author_name") else extract_username(url),
                "author_pfp": None,
                "source": "oembed"
            }
    except Exception as e:
        print(f"oEmbed error: {e}")
    return None

# ============================================================
# AUTH ENDPOINTS
# ============================================================

@app.route("/auth/login")
def login():
    """Start Twitter OAuth flow"""
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    state = secrets.token_urlsafe(16)
    
    session['code_verifier'] = code_verifier
    session['state'] = state
    
    params = {
        "response_type": "code",
        "client_id": TWITTER_CLIENT_ID,
        "redirect_uri": TWITTER_REDIRECT_URI,
        "scope": "tweet.read users.read",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256"
    }
    
    auth_url = f"https://twitter.com/i/oauth2/authorize?{urlencode(params)}"
    return redirect(auth_url)

@app.route("/callback")
def callback():
    """Handle Twitter OAuth callback"""
    code = request.args.get("code")
    state = request.args.get("state")
    error = request.args.get("error")
    
    if error:
        return redirect(f"{FRONTEND_URL}?error={error}")
    
    if state != session.get('state'):
        return redirect(f"{FRONTEND_URL}?error=invalid_state")
    
    code_verifier = session.get('code_verifier')
    
    # Exchange code for token
    token_url = "https://api.twitter.com/2/oauth2/token"
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": TWITTER_REDIRECT_URI,
        "code_verifier": code_verifier
    }
    
    credentials = base64.b64encode(f"{TWITTER_CLIENT_ID}:{TWITTER_CLIENT_SECRET}".encode()).decode()
    token_headers = {
        "Authorization": f"Basic {credentials}",
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    token_response = requests.post(token_url, data=token_data, headers=token_headers, timeout=10)
    
    if token_response.status_code != 200:
        print(f"Token error: {token_response.text}")
        return redirect(f"{FRONTEND_URL}?error=token_failed")
    
    token_json = token_response.json()
    access_token = token_json.get("access_token")
    
    # Fetch user info
    user_url = "https://api.twitter.com/2/users/me?user.fields=profile_image_url,username,name"
    user_headers = {"Authorization": f"Bearer {access_token}"}
    user_response = requests.get(user_url, headers=user_headers, timeout=10)
    
    if user_response.status_code != 200:
        print(f"User fetch error: {user_response.text}")
        return redirect(f"{FRONTEND_URL}?error=user_fetch_failed")
    
    user_data = user_response.json().get("data", {})
    
    # Save/update user in database
    conn = get_db()
    cursor = get_cursor(conn)
    
    cursor.execute('''
        INSERT INTO users (id, username, name, pfp, access_token)
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT(id) DO UPDATE SET
            username = excluded.username,
            name = excluded.name,
            pfp = excluded.pfp,
            access_token = excluded.access_token
    ''', (
        user_data.get("id"),
        user_data.get("username"),
        user_data.get("name"),
        user_data.get("profile_image_url", "").replace("_normal", "_400x400"),
        access_token
    ))
    
    # Create session
    session_token = secrets.token_urlsafe(32)
    cursor.execute('INSERT INTO sessions (token, user_id) VALUES (%s, %s)', 
                   (session_token, user_data.get("id")))
    
    conn.commit()
    conn.close()
    
    return redirect(f"{FRONTEND_URL}?token={session_token}")

@app.route("/auth/me")
def get_me():
    """Get current user info"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    
    vote_status = get_user_vote_status(user["id"])
    
    return jsonify({
        "id": user["id"],
        "username": user["username"],
        "name": user["name"],
        "pfp": user["pfp"],
        "is_admin": is_admin(user),
        **vote_status
    })

@app.route("/auth/logout", methods=["POST"])
def logout():
    """Logout user"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    if token:
        conn = get_db()
        cursor = get_cursor(conn)
        cursor.execute('DELETE FROM sessions WHERE token = %s', (token,))
        conn.commit()
        conn.close()
    return jsonify({"success": True})

# ============================================================
# POST ENDPOINTS
# ============================================================

@app.route("/preview", methods=["POST"])
def get_preview():
    """Fetch preview for a Twitter/X URL"""
    data = request.get_json()
    
    if not data or not data.get("url"):
        return jsonify({"error": "URL is required"}), 400
    
    url = data["url"].strip()
    
    if not is_twitter_url(url):
        return jsonify({"error": "Only Twitter/X URLs are supported"}), 400
    
    tweet_id = extract_tweet_id(url)
    if not tweet_id:
        return jsonify({"error": "Invalid tweet URL"}), 400
    
    result = None
    
    print(f"Trying vxtwitter for {tweet_id}...")
    result = fetch_via_vxtwitter(url)
    
    if not result or (not result.get("image") and not result.get("text")):
        print(f"Trying fxtwitter for {tweet_id}...")
        fx_result = fetch_via_fxtwitter(url)
        if fx_result:
            if not result:
                result = fx_result
            else:
                if not result.get("image"):
                    result["image"] = fx_result.get("image")
                if not result.get("text"):
                    result["text"] = fx_result.get("text")
    
    if not result or not result.get("text"):
        print(f"Trying oEmbed for {tweet_id}...")
        oembed_result = fetch_via_oembed(url)
        if oembed_result:
            if not result:
                result = oembed_result
            else:
                if not result.get("text"):
                    result["text"] = oembed_result.get("text")
                if not result.get("author"):
                    result["author"] = oembed_result.get("author")
    
    if not result or (not result.get("text") and not result.get("image")):
        return jsonify({"error": "Unable to fetch tweet preview"}), 422
    
    print(f"Success! Image: {'Yes' if result.get('image') else 'No'}")
    return jsonify(result)

@app.route("/posts/<int:post_id>/refetch", methods=["GET"])
def refetch_post_text(post_id):
    """Re-fetch FULL tweet text from X for detailed view"""
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Post not found"}), 404
    
    post = post_to_dict(row)
    url = post.get("url")
    
    if not url:
        return jsonify({"error": "No URL for post"}), 400
    
    # Try to fetch FULL text via vxtwitter API
    try:
        tweet_id = extract_tweet_id(url)
        api_url = f"https://api.vxtwitter.com/Twitter/status/{tweet_id}"
        response = requests.get(api_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            full_text = data.get("text", "")
            
            # Clean up URLs but PRESERVE line breaks
            if full_text:
                full_text = re.sub(r'https?://\S+', '', full_text)
                full_text = re.sub(r't\.co/\S+', '', full_text)
                # Only collapse multiple spaces, keep newlines
                full_text = re.sub(r'[^\S\n]+', ' ', full_text)
                full_text = full_text.strip()
            
            if full_text:
                return jsonify({
                    "text": full_text,
                    "full_text": True
                })
    except Exception as e:
        print(f"Refetch vxtwitter error: {e}")
    
    # Try fxtwitter as fallback
    try:
        tweet_id = extract_tweet_id(url)
        fx_url = f"https://api.fxtwitter.com/status/{tweet_id}"
        response = requests.get(fx_url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get("tweet"):
                full_text = data["tweet"].get("text", "")
                if full_text:
                    full_text = re.sub(r'https?://\S+', '', full_text)
                    full_text = re.sub(r't\.co/\S+', '', full_text)
                    # Only collapse multiple spaces, keep newlines
                    full_text = re.sub(r'[^\S\n]+', ' ', full_text)
                    full_text = full_text.strip()
                    return jsonify({
                        "text": full_text,
                        "full_text": True
                    })
    except Exception as e:
        print(f"Refetch fxtwitter error: {e}")
    
    # Return existing text if refetch failed
    return jsonify({
        "text": post.get("text", ""),
        "full_text": False
    })

@app.route("/posts", methods=["GET"])
def get_posts():
    """Get all posts"""
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('SELECT * FROM posts ORDER BY created_at DESC')
    rows = cursor.fetchall()
    conn.close()
    
    posts = [post_to_dict(row) for row in rows]
    return jsonify(posts)

@app.route("/posts", methods=["POST"])
def create_post():
    """Create a new post"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    data = request.get_json()
    
    if not user:
        return jsonify({"error": "Must be logged in to post"}), 401
    
    # Verify user owns the tweet
    tweet_author = (data.get("author", "").replace("@", "").lower())
    if tweet_author != user["username"].lower():
        return jsonify({"error": "You can only share your own tweets"}), 403
    
    categories = data.get("categories", [])
    if not categories:
        return jsonify({"error": "Select at least 1 category"}), 400
    
    # Extract tweet ID from URL to check for duplicates
    url = data.get("url", "")
    tweet_id = extract_tweet_id(url)
    
    if not tweet_id:
        return jsonify({"error": "Invalid tweet URL"}), 400
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    # Check if this tweet ID was already posted (by anyone)
    # Search for the tweet ID in the URL (handles both with and without query params)
    cursor.execute('SELECT id FROM posts WHERE url LIKE %s', (f'%/status/{tweet_id}%',))
    existing = cursor.fetchone()
    
    if existing:
        conn.close()
        return jsonify({"error": "This tweet has already been shared"}), 409
    
    # Store clean URL without query params
    clean_url = f"https://x.com/{tweet_author}/status/{tweet_id}"
    
    cursor.execute('''
        INSERT INTO posts (url, image, text, author, author_pfp, categories, user_id, user_username)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    ''', (
        clean_url,
        data.get("image"),
        data.get("text"),
        data.get("author"),
        data.get("author_pfp"),
        json.dumps(categories),
        user["id"],
        user["username"]
    ))
    
    post_id = cursor.fetchone()['id']
    conn.commit()
    
    cursor.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    row = cursor.fetchone()
    
    conn.close()
    
    return jsonify(post_to_dict(row)), 201

@app.route("/posts/<int:post_id>", methods=["DELETE"])
def delete_post(post_id):
    """Delete a post"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({"error": "Must be logged in"}), 401
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    cursor.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    post = cursor.fetchone()
    
    if not post:
        conn.close()
        return jsonify({"error": "Post not found"}), 404
    
    # Allow deletion if user owns the post OR is admin
    if post["user_id"] != user["id"] and not is_admin(user):
        conn.close()
        return jsonify({"error": "Not authorized"}), 403
    
    cursor.execute('DELETE FROM votes WHERE post_id = %s', (post_id,))
    cursor.execute('DELETE FROM posts WHERE id = %s', (post_id,))
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

@app.route("/posts/<int:post_id>/categories", methods=["PUT"])
def update_post_categories(post_id):
    """Update post categories (admin only)"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({"error": "Must be logged in"}), 401
    
    if not is_admin(user):
        return jsonify({"error": "Admin access required"}), 403
    
    data = request.get_json()
    categories = data.get("categories", [])
    
    if not categories:
        return jsonify({"error": "At least one category required"}), 400
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    cursor.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    post = cursor.fetchone()
    
    if not post:
        conn.close()
        return jsonify({"error": "Post not found"}), 404
    
    cursor.execute(
        'UPDATE posts SET categories = %s WHERE id = %s',
        (json.dumps(categories), post_id)
    )
    
    conn.commit()
    
    # Return updated post
    cursor.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    updated_post = cursor.fetchone()
    conn.close()
    
    return jsonify(post_to_dict(updated_post))

@app.route("/posts/<int:post_id>/vote", methods=["POST"])
def vote_post(post_id):
    """Vote on a post"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    data = request.get_json()
    vote_type = data.get("type")  # "up" or "down"
    
    if not user:
        return jsonify({"error": "Must be logged in to vote"}), 401
    
    # Check daily vote status
    vote_status = get_user_vote_status(user["id"])
    
    if not vote_status['can_vote']:
        return jsonify({"error": f"Rate {vote_status['ratings_needed']} more posts to unlock voting today"}), 403
    
    if vote_status['votes_remaining'] <= 0:
        return jsonify({"error": "You've reached your daily vote limit (20)"}), 403
    
    if vote_type not in ["up", "down"]:
        return jsonify({"error": "Invalid vote type"}), 400
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    # Check if post exists
    cursor.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    post = cursor.fetchone()
    if not post:
        conn.close()
        return jsonify({"error": "Post not found"}), 404
    
    # Check existing vote
    cursor.execute('SELECT * FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user["id"]))
    existing_vote = cursor.fetchone()
    
    if existing_vote:
        old_type = existing_vote["vote_type"]
        
        if old_type == vote_type:
            # Same vote - remove it (toggle off) - doesn't cost a vote
            cursor.execute('DELETE FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user["id"]))
            if vote_type == "up":
                cursor.execute('UPDATE posts SET likes = likes - 1 WHERE id = %s', (post_id,))
            else:
                cursor.execute('UPDATE posts SET dislikes = dislikes - 1 WHERE id = %s', (post_id,))
        else:
            # Different vote - change it - doesn't cost a vote
            cursor.execute('UPDATE votes SET vote_type = %s WHERE post_id = %s AND user_id = %s', 
                          (vote_type, post_id, user["id"]))
            if vote_type == "up":
                cursor.execute('UPDATE posts SET likes = likes + 1, dislikes = dislikes - 1 WHERE id = %s', (post_id,))
            else:
                cursor.execute('UPDATE posts SET likes = likes - 1, dislikes = dislikes + 1 WHERE id = %s', (post_id,))
    else:
        # New vote - costs 1 daily vote
        cursor.execute('INSERT INTO votes (post_id, user_id, vote_type, is_rating) VALUES (%s, %s, %s, 0)',
                      (post_id, user["id"], vote_type))
        if vote_type == "up":
            cursor.execute('UPDATE posts SET likes = likes + 1 WHERE id = %s', (post_id,))
        else:
            cursor.execute('UPDATE posts SET dislikes = dislikes + 1 WHERE id = %s', (post_id,))
        
        # Increment daily vote count
        cursor.execute('UPDATE users SET votes_today = votes_today + 1 WHERE id = %s', (user["id"],))
    
    conn.commit()
    
    # Return updated post
    cursor.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    updated_post = cursor.fetchone()
    
    # Get user's current vote
    cursor.execute('SELECT vote_type FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user["id"]))
    user_vote = cursor.fetchone()
    
    conn.close()
    
    result = post_to_dict(updated_post)
    result["user_vote"] = user_vote["vote_type"] if user_vote else None
    
    return jsonify(result)

@app.route("/posts/<int:post_id>/vote", methods=["GET"])
def get_vote(post_id):
    """Get user's vote on a post"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({"vote": None})
    
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('SELECT vote_type FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user["id"]))
    vote = cursor.fetchone()
    conn.close()
    
    return jsonify({"vote": vote["vote_type"] if vote else None})

@app.route("/user/votes", methods=["GET"])
def get_user_votes():
    """Get all votes by current user"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({})
    
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('SELECT post_id, vote_type FROM votes WHERE user_id = %s', (user["id"],))
    rows = cursor.fetchall()
    conn.close()
    
    votes = {row["post_id"]: row["vote_type"] for row in rows}
    return jsonify(votes)

@app.route("/rating/posts", methods=["GET"])
def get_rating_posts():
    """Get random posts for rating (posts user hasn't voted on)"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({"error": "Must be logged in"}), 401
    
    vote_status = get_user_vote_status(user["id"])
    
    # If user has already rated enough today, return empty
    if vote_status['can_vote']:
        return jsonify({"posts": [], "ratings_needed": 0})
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    # Get posts user hasn't voted on yet
    cursor.execute('''
        SELECT p.* FROM posts p
        WHERE p.id NOT IN (
            SELECT post_id FROM votes WHERE user_id = %s
        )
        ORDER BY RANDOM()
        LIMIT %s
    ''', (user["id"], vote_status['ratings_needed']))
    
    rows = cursor.fetchall()
    conn.close()
    
    posts = [post_to_dict(row) for row in rows]
    
    return jsonify({
        "posts": posts,
        "ratings_needed": vote_status['ratings_needed'],
        "ratings_today": vote_status['ratings_today']
    })

@app.route("/rating/submit", methods=["POST"])
def submit_rating():
    """Submit a rating vote (during rating phase)"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    data = request.get_json()
    
    if not user:
        return jsonify({"error": "Must be logged in"}), 401
    
    post_id = data.get("post_id")
    vote_type = data.get("type")  # "up" or "down"
    
    if not post_id or vote_type not in ["up", "down"]:
        return jsonify({"error": "Invalid request"}), 400
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    # Check if post exists
    cursor.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    post = cursor.fetchone()
    if not post:
        conn.close()
        return jsonify({"error": "Post not found"}), 404
    
    # Check if already voted on this post
    cursor.execute('SELECT id FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user["id"]))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "Already voted on this post"}), 409
    
    # Add the vote (marked as rating)
    cursor.execute('INSERT INTO votes (post_id, user_id, vote_type, is_rating) VALUES (%s, %s, %s, 1)',
                  (post_id, user["id"], vote_type))
    
    # Update post likes/dislikes
    if vote_type == "up":
        cursor.execute('UPDATE posts SET likes = likes + 1 WHERE id = %s', (post_id,))
    else:
        cursor.execute('UPDATE posts SET dislikes = dislikes + 1 WHERE id = %s', (post_id,))
    
    # Increment user's rating count for today
    today = get_today()
    cursor.execute('''
        UPDATE users SET ratings_today = ratings_today + 1, last_vote_reset = %s
        WHERE id = %s
    ''', (today, user["id"]))
    
    conn.commit()
    conn.close()
    
    # Return updated status
    vote_status = get_user_vote_status(user["id"])
    
    return jsonify({
        "success": True,
        **vote_status
    })

@app.route("/posts/random", methods=["GET"])
def get_random_posts():
    """Get 5 random posts for rating gate"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    if user:
        # Get posts not owned by this user
        cursor.execute('''
            SELECT * FROM posts 
            WHERE user_id != %s 
            ORDER BY RANDOM() 
            LIMIT 5
        ''', (user["id"],))
    else:
        cursor.execute('SELECT * FROM posts ORDER BY RANDOM() LIMIT 5')
    
    rows = cursor.fetchall()
    conn.close()
    
    return jsonify([post_to_dict(row) for row in rows])

@app.route("/user/rate", methods=["POST"])
def rate_for_unlock():
    """Rate a post during the unlock phase (before can_vote is true)"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    data = request.get_json()
    
    if not user:
        return jsonify({"error": "Must be logged in"}), 401
    
    # If already can vote, use normal vote endpoint
    if user.get("can_vote"):
        return jsonify({"error": "Already unlocked, use /posts/{id}/vote"}), 400
    
    post_id = data.get("post_id")
    vote_type = data.get("type")  # "up" or "down"
    
    if not post_id or vote_type not in ["up", "down"]:
        return jsonify({"error": "Invalid request"}), 400
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    # Check if post exists
    cursor.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    post = cursor.fetchone()
    if not post:
        conn.close()
        return jsonify({"error": "Post not found"}), 404
    
    # Check if already voted on this post
    cursor.execute('SELECT * FROM votes WHERE post_id = %s AND user_id = %s', (post_id, user["id"]))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "Already rated this post"}), 400
    
    # Add vote
    cursor.execute('INSERT INTO votes (post_id, user_id, vote_type) VALUES (%s, %s, %s)',
                  (post_id, user["id"], vote_type))
    
    # Update post counts
    if vote_type == "up":
        cursor.execute('UPDATE posts SET likes = likes + 1 WHERE id = %s', (post_id,))
    else:
        cursor.execute('UPDATE posts SET dislikes = dislikes + 1 WHERE id = %s', (post_id,))
    
    # Update user's rating count
    new_count = user.get("rating_count", 0) + 1
    can_vote = 1 if new_count >= 5 else 0
    
    cursor.execute('UPDATE users SET rating_count = %s, can_vote = %s WHERE id = %s',
                  (new_count, can_vote, user["id"]))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        "success": True,
        "rating_count": new_count,
        "can_vote": bool(can_vote)
    })

# ============================================================
# AI SLOP REPORT ENDPOINTS
# ============================================================

@app.route("/posts/<int:post_id>/slop", methods=["POST"])
def report_slop(post_id):
    """Report a post as AI Slop with reason"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    data = request.get_json()
    
    if not user:
        return jsonify({"error": "Must be logged in"}), 401
    
    reason = data.get("reason", "").strip()
    if not reason:
        return jsonify({"error": "Please explain why this is AI slop"}), 400
    
    if len(reason) > 500:
        return jsonify({"error": "Reason too long (max 500 characters)"}), 400
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    # Check if post exists
    cursor.execute('SELECT * FROM posts WHERE id = %s', (post_id,))
    post = cursor.fetchone()
    if not post:
        conn.close()
        return jsonify({"error": "Post not found"}), 404
    
    # Check if user already reported this post
    cursor.execute('SELECT id FROM slop_reports WHERE post_id = %s AND user_id = %s', (post_id, user["id"]))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "You already reported this post"}), 409
    
    # Add slop report
    cursor.execute('''
        INSERT INTO slop_reports (post_id, user_id, username, reason)
        VALUES (%s, %s, %s, %s)
    ''', (post_id, user["id"], user["username"], reason))
    
    # Update slop count on post
    cursor.execute('UPDATE posts SET slop_count = slop_count + 1 WHERE id = %s', (post_id,))
    
    conn.commit()
    
    # Get updated slop count
    cursor.execute('SELECT slop_count FROM posts WHERE id = %s', (post_id,))
    slop_count = cursor.fetchone()['slop_count']
    
    conn.close()
    
    return jsonify({
        "success": True,
        "slop_count": slop_count
    })

@app.route("/posts/<int:post_id>/slop", methods=["GET"])
def get_slop_reports(post_id):
    """Get all AI Slop reports for a post"""
    conn = get_db()
    cursor = get_cursor(conn)
    
    cursor.execute('''
        SELECT username, reason, created_at 
        FROM slop_reports 
        WHERE post_id = %s
        ORDER BY created_at DESC
    ''', (post_id,))
    
    reports = []
    for row in cursor.fetchall():
        created_at = str(row['created_at'])
        if not created_at.endswith('Z') and '+' not in created_at:
            created_at = created_at.replace(' ', 'T') + 'Z'
        reports.append({
            'username': row['username'],
            'reason': row['reason'],
            'created_at': created_at
        })
    
    conn.close()
    
    return jsonify(reports)

@app.route("/posts/<int:post_id>/slop/check", methods=["GET"])
def check_user_slop(post_id):
    """Check if current user has reported this post"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = get_user_from_token(token)
    
    if not user:
        return jsonify({"reported": False})
    
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('SELECT id FROM slop_reports WHERE post_id = %s AND user_id = %s', (post_id, user["id"]))
    reported = cursor.fetchone() is not None
    conn.close()
    
    return jsonify({"reported": reported})

# ============================================================
# USER PROFILE & FOLLOW ENDPOINTS
# ============================================================

def get_user_stats(user_id, cursor):
    """Get follower/following counts for a user"""
    cursor.execute('SELECT COUNT(*) as count FROM follows WHERE following_id = %s', (user_id,))
    followers = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM follows WHERE follower_id = %s', (user_id,))
    following = cursor.fetchone()['count']
    
    cursor.execute('SELECT COUNT(*) as count FROM posts WHERE user_id = %s', (user_id,))
    posts_count = cursor.fetchone()['count']
    
    cursor.execute('SELECT SUM(likes) as total FROM posts WHERE user_id = %s', (user_id,))
    result = cursor.fetchone()
    total_likes = result['total'] if result['total'] else 0
    
    return {
        'followers': followers,
        'following': following,
        'posts_count': posts_count,
        'total_likes': total_likes
    }

@app.route("/users/<username>", methods=["GET"])
def get_user_profile(username):
    """Get public profile of a user"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    current_user = get_user_from_token(token)
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    cursor.execute('SELECT id, username, name, pfp, bio, created_at FROM users WHERE username = %s', (username,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    stats = get_user_stats(user['id'], cursor)
    
    # Check if current user follows this user
    is_following = False
    is_own_profile = False
    if current_user:
        is_own_profile = current_user['id'] == user['id']
        if not is_own_profile:
            cursor.execute('SELECT id FROM follows WHERE follower_id = %s AND following_id = %s', 
                          (current_user['id'], user['id']))
            is_following = cursor.fetchone() is not None
    
    # Get user's posts
    cursor.execute('''
        SELECT * FROM posts WHERE user_id = %s ORDER BY created_at DESC
    ''', (user['id'],))
    posts = [post_to_dict(row) for row in cursor.fetchall()]
    
    conn.close()
    
    created_at = str(user['created_at'])
    if not created_at.endswith('Z') and '+' not in created_at:
        created_at = created_at.replace(' ', 'T') + 'Z'
    
    return jsonify({
        'id': user['id'],
        'username': user['username'],
        'name': user['name'],
        'pfp': user['pfp'],
        'bio': user['bio'] or '',
        'created_at': created_at,
        'is_following': is_following,
        'is_own_profile': is_own_profile,
        **stats,
        'posts': posts
    })

@app.route("/users/<username>/follow", methods=["POST"])
def follow_user(username):
    """Follow a user"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    current_user = get_user_from_token(token)
    
    if not current_user:
        return jsonify({"error": "Must be logged in"}), 401
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    target_user = cursor.fetchone()
    
    if not target_user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    if target_user['id'] == current_user['id']:
        conn.close()
        return jsonify({"error": "Cannot follow yourself"}), 400
    
    # Check if already following
    cursor.execute('SELECT id FROM follows WHERE follower_id = %s AND following_id = %s',
                  (current_user['id'], target_user['id']))
    if cursor.fetchone():
        conn.close()
        return jsonify({"error": "Already following"}), 409
    
    # Create follow
    cursor.execute('INSERT INTO follows (follower_id, following_id) VALUES (%s, %s)',
                  (current_user['id'], target_user['id']))
    conn.commit()
    
    # Get updated counts
    stats = get_user_stats(target_user['id'], cursor)
    conn.close()
    
    return jsonify({
        "success": True,
        "is_following": True,
        **stats
    })

@app.route("/users/<username>/unfollow", methods=["POST"])
def unfollow_user(username):
    """Unfollow a user"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    current_user = get_user_from_token(token)
    
    if not current_user:
        return jsonify({"error": "Must be logged in"}), 401
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    target_user = cursor.fetchone()
    
    if not target_user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    cursor.execute('DELETE FROM follows WHERE follower_id = %s AND following_id = %s',
                  (current_user['id'], target_user['id']))
    conn.commit()
    
    # Get updated counts
    stats = get_user_stats(target_user['id'], cursor)
    conn.close()
    
    return jsonify({
        "success": True,
        "is_following": False,
        **stats
    })

@app.route("/users/<username>/followers", methods=["GET"])
def get_followers(username):
    """Get list of followers for a user"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    current_user = get_user_from_token(token)
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    target_user = cursor.fetchone()
    
    if not target_user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    cursor.execute('''
        SELECT u.id, u.username, u.name, u.pfp 
        FROM users u
        JOIN follows f ON f.follower_id = u.id
        WHERE f.following_id = %s
        ORDER BY f.created_at DESC
    ''', (target_user['id'],))
    
    followers = []
    for row in cursor.fetchall():
        is_following = False
        if current_user:
            cursor.execute('SELECT id FROM follows WHERE follower_id = %s AND following_id = %s',
                          (current_user['id'], row['id']))
            is_following = cursor.fetchone() is not None
        
        followers.append({
            'id': row['id'],
            'username': row['username'],
            'name': row['name'],
            'pfp': row['pfp'],
            'is_following': is_following
        })
    
    conn.close()
    return jsonify(followers)

@app.route("/users/<username>/following", methods=["GET"])
def get_following(username):
    """Get list of users that a user follows"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    current_user = get_user_from_token(token)
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    cursor.execute('SELECT id FROM users WHERE username = %s', (username,))
    target_user = cursor.fetchone()
    
    if not target_user:
        conn.close()
        return jsonify({"error": "User not found"}), 404
    
    cursor.execute('''
        SELECT u.id, u.username, u.name, u.pfp 
        FROM users u
        JOIN follows f ON f.following_id = u.id
        WHERE f.follower_id = %s
        ORDER BY f.created_at DESC
    ''', (target_user['id'],))
    
    following = []
    for row in cursor.fetchall():
        is_following = False
        if current_user:
            cursor.execute('SELECT id FROM follows WHERE follower_id = %s AND following_id = %s',
                          (current_user['id'], row['id']))
            is_following = cursor.fetchone() is not None
        
        following.append({
            'id': row['id'],
            'username': row['username'],
            'name': row['name'],
            'pfp': row['pfp'],
            'is_following': is_following
        })
    
    conn.close()
    return jsonify(following)

@app.route("/feed/following", methods=["GET"])
def get_following_feed():
    """Get posts from users the current user follows"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    current_user = get_user_from_token(token)
    
    if not current_user:
        return jsonify({"error": "Must be logged in"}), 401
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    # Get posts from followed users
    cursor.execute('''
        SELECT p.* FROM posts p
        JOIN follows f ON f.following_id = p.user_id
        WHERE f.follower_id = %s
        ORDER BY p.created_at DESC
    ''', (current_user['id'],))
    
    posts = [post_to_dict(row) for row in cursor.fetchall()]
    conn.close()
    
    return jsonify(posts)

@app.route("/users/<username>/bio", methods=["PUT"])
def update_bio(username):
    """Update user bio"""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    current_user = get_user_from_token(token)
    
    if not current_user:
        return jsonify({"error": "Must be logged in"}), 401
    
    if current_user['username'] != username:
        return jsonify({"error": "Can only edit your own bio"}), 403
    
    data = request.get_json()
    bio = data.get('bio', '')[:160]  # Limit to 160 chars
    
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('UPDATE users SET bio = %s WHERE id = %s', (bio, current_user['id']))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "bio": bio})

# ============================================================
# LEADERBOARD ENDPOINTS
# ============================================================

CATEGORIES = ['art', 'video', 'meme', 'tech', 'shitpost', 'testnet']

@app.route("/leaderboard/current-week", methods=["GET"])
def get_current_week_posts():
    """Get posts from current week (Monday 00:00 to Sunday 23:59) for 7D tab"""
    monday, sunday = get_current_week_bounds()
    
    # Use consistent date format with SQLite (space separator, not T)
    monday_str = monday.strftime('%Y-%m-%d %H:%M:%S')
    sunday_str = sunday.strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('''
        SELECT * FROM posts 
        WHERE created_at >= %s AND created_at <= %s
        ORDER BY likes DESC
    ''', (monday_str, sunday_str))
    rows = cursor.fetchall()
    conn.close()
    
    posts = [post_to_dict(row) for row in rows]
    return jsonify({
        "posts": posts,
        "week_start": monday.strftime('%Y-%m-%d'),
        "week_end": sunday.strftime('%Y-%m-%d'),
        "week_label": format_week_label(monday, sunday)
    })

@app.route("/leaderboard/archive", methods=["GET"])
def get_leaderboard_archive():
    """Get all saved weekly leaderboards - also auto-finalizes past weeks"""
    
    # Auto-finalize any past weeks that haven't been saved yet
    auto_finalize_past_weeks()
    
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('''
        SELECT DISTINCT week_start, week_end 
        FROM weekly_leaderboard 
        ORDER BY week_start DESC
    ''')
    weeks = cursor.fetchall()
    conn.close()
    
    result = []
    for week in weeks:
        monday = datetime.strptime(week['week_start'], '%Y-%m-%d')
        sunday = datetime.strptime(week['week_end'], '%Y-%m-%d')
        result.append({
            "week_start": week['week_start'],
            "week_end": week['week_end'],
            "label": format_week_label(monday, sunday)
        })
    
    return jsonify(result)

def auto_finalize_past_weeks():
    """Automatically finalize any past weeks that haven't been saved yet"""
    conn = get_db()
    cursor = get_cursor(conn)
    
    # Get the earliest post date to know how far back to check
    cursor.execute('SELECT MIN(created_at) as earliest FROM posts')
    row = cursor.fetchone()
    if not row or not row['earliest']:
        conn.close()
        return
    
    # PostgreSQL returns datetime object directly
    earliest_post = row['earliest']
    if isinstance(earliest_post, str):
        earliest_post = datetime.fromisoformat(earliest_post.replace('Z', '+00:00').split('+')[0])
    
    today = datetime.utcnow()
    
    # Get current week's Monday (we don't finalize current week)
    current_monday = today - timedelta(days=today.weekday())
    current_monday = current_monday.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Start from the week of the earliest post
    check_monday = earliest_post - timedelta(days=earliest_post.weekday())
    check_monday = check_monday.replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Check each past week
    while check_monday < current_monday:
        week_start = check_monday.strftime('%Y-%m-%d')
        week_end = (check_monday + timedelta(days=6)).strftime('%Y-%m-%d')
        
        # Check if this week is already finalized
        cursor.execute('SELECT COUNT(*) as count FROM weekly_leaderboard WHERE week_start = %s', (week_start,))
        if cursor.fetchone()['count'] == 0:
            # Finalize this week
            finalize_week(cursor, check_monday, check_monday + timedelta(days=6, hours=23, minutes=59, seconds=59))
        
        # Move to next week
        check_monday += timedelta(days=7)
    
    conn.commit()
    conn.close()

def finalize_week(cursor, monday, sunday):
    """Finalize a specific week's leaderboard"""
    week_start = monday.strftime('%Y-%m-%d')
    week_end = sunday.strftime('%Y-%m-%d')
    
    # Use consistent date format with SQLite (space separator, not T)
    monday_str = monday.strftime('%Y-%m-%d %H:%M:%S')
    sunday_str = sunday.strftime('%Y-%m-%d %H:%M:%S')
    
    for category in CATEGORIES:
        cursor.execute('''
            SELECT p.*, u.name as user_name, u.pfp as user_pfp
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.created_at >= %s AND p.created_at <= %s
            AND p.categories LIKE %s
            ORDER BY p.likes DESC
            LIMIT 3
        ''', (monday_str, sunday_str, f'%{category}%'))
        
        top_posts = cursor.fetchall()
        
        for rank, post in enumerate(top_posts, 1):
            try:
                cursor.execute('''
                    INSERT INTO weekly_leaderboard 
                    (week_start, week_end, category, rank, post_id, post_url, post_image, post_text,
                     user_id, user_username, user_name, user_pfp, likes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ''', (
                    week_start, week_end, category, rank,
                    post['id'], post['url'], post['image'], post['text'],
                    post['user_id'], post['user_username'], post['user_name'], post['user_pfp'],
                    post['likes']
                ))
            except:
                pass  # Skip if already exists

@app.route("/leaderboard/week/<week_start>", methods=["GET"])
def get_leaderboard_for_week(week_start):
    """Get leaderboard for a specific week"""
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('''
        SELECT * FROM weekly_leaderboard 
        WHERE week_start = %s
        ORDER BY category, rank
    ''', (week_start,))
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        return jsonify({"error": "No leaderboard found for this week"}), 404
    
    # Group by category
    leaderboard = {}
    week_end = None
    for row in rows:
        cat = row['category']
        week_end = row['week_end']
        if cat not in leaderboard:
            leaderboard[cat] = []
        leaderboard[cat].append({
            "rank": row['rank'],
            "post_id": row['post_id'],
            "post_url": row['post_url'],
            "post_image": row['post_image'],
            "post_text": row['post_text'],
            "user_id": row['user_id'],
            "user_username": row['user_username'],
            "user_name": row['user_name'],
            "user_pfp": row['user_pfp'],
            "likes": row['likes']
        })
    
    monday = datetime.strptime(week_start, '%Y-%m-%d')
    sunday = datetime.strptime(week_end, '%Y-%m-%d') if week_end else monday + timedelta(days=6)
    
    return jsonify({
        "week_start": week_start,
        "week_end": week_end,
        "label": format_week_label(monday, sunday),
        "categories": leaderboard
    })

@app.route("/leaderboard/finalize-week", methods=["POST"])
def finalize_week_leaderboard():
    """
    Finalize the leaderboard for the previous week.
    Should be called after Sunday 23:59 (e.g., Monday morning via cron job)
    Or can be triggered manually.
    """
    # Get previous week bounds (UTC)
    today = datetime.utcnow()
    # Go back to last week
    last_monday = today - timedelta(days=today.weekday() + 7)
    last_monday = last_monday.replace(hour=0, minute=0, second=0, microsecond=0)
    last_sunday = last_monday + timedelta(days=6, hours=23, minutes=59, seconds=59)
    
    week_start = last_monday.strftime('%Y-%m-%d')
    week_end = last_sunday.strftime('%Y-%m-%d')
    
    # Use consistent date format with SQLite (space separator, not T)
    last_monday_str = last_monday.strftime('%Y-%m-%d %H:%M:%S')
    last_sunday_str = last_sunday.strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    # Check if already finalized
    cursor.execute('SELECT COUNT(*) as count FROM weekly_leaderboard WHERE week_start = %s', (week_start,))
    if cursor.fetchone()['count'] > 0:
        conn.close()
        return jsonify({"message": "Week already finalized", "week_start": week_start})
    
    # Get top 3 posts for each category from that week
    for category in CATEGORIES:
        cursor.execute('''
            SELECT p.*, u.name as user_name, u.pfp as user_pfp
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.created_at >= %s AND p.created_at <= %s
            AND p.categories LIKE %s
            ORDER BY p.likes DESC
            LIMIT 3
        ''', (last_monday_str, last_sunday_str, f'%{category}%'))
        
        top_posts = cursor.fetchall()
        
        for rank, post in enumerate(top_posts, 1):
            cursor.execute('''
                INSERT INTO weekly_leaderboard 
                (week_start, week_end, category, rank, post_id, post_url, post_image, post_text,
                 user_id, user_username, user_name, user_pfp, likes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                week_start, week_end, category, rank,
                post['id'], post['url'], post['image'], post['text'],
                post['user_id'], post['user_username'], post['user_name'], post['user_pfp'],
                post['likes']
            ))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        "success": True,
        "week_start": week_start,
        "week_end": week_end,
        "label": format_week_label(last_monday, last_sunday)
    })

@app.route("/leaderboard/finalize-current", methods=["POST"])
def finalize_current_week():
    """
    Finalize the CURRENT week leaderboard (for testing purposes).
    Use this to test the leaderboard without waiting for the week to end.
    """
    monday, sunday = get_current_week_bounds()
    
    week_start = monday.strftime('%Y-%m-%d')
    week_end = sunday.strftime('%Y-%m-%d')
    
    # Use consistent date format with SQLite (space separator, not T)
    monday_str = monday.strftime('%Y-%m-%d %H:%M:%S')
    sunday_str = sunday.strftime('%Y-%m-%d %H:%M:%S')
    
    conn = get_db()
    cursor = get_cursor(conn)
    
    # Delete existing entries for this week (allow re-finalize for testing)
    cursor.execute('DELETE FROM weekly_leaderboard WHERE week_start = %s', (week_start,))
    
    # Get top 3 posts for each category from current week
    for category in CATEGORIES:
        cursor.execute('''
            SELECT p.*, u.name as user_name, u.pfp as user_pfp
            FROM posts p
            LEFT JOIN users u ON p.user_id = u.id
            WHERE p.created_at >= %s AND p.created_at <= %s
            AND p.categories LIKE %s
            ORDER BY p.likes DESC
            LIMIT 3
        ''', (monday_str, sunday_str, f'%{category}%'))
        
        top_posts = cursor.fetchall()
        
        for rank, post in enumerate(top_posts, 1):
            cursor.execute('''
                INSERT INTO weekly_leaderboard 
                (week_start, week_end, category, rank, post_id, post_url, post_image, post_text,
                 user_id, user_username, user_name, user_pfp, likes)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ''', (
                week_start, week_end, category, rank,
                post['id'], post['url'], post['image'], post['text'],
                post['user_id'], post['user_username'], post['user_name'], post['user_pfp'],
                post['likes']
            ))
    
    conn.commit()
    conn.close()
    
    return jsonify({
        "success": True,
        "week_start": week_start,
        "week_end": week_end,
        "label": format_week_label(monday, sunday),
        "message": "Current week finalized for testing"
    })

@app.route("/leaderboard/clear-all", methods=["GET"])
def clear_leaderboard():
    """Clear all leaderboard data (for cleaning up test data)"""
    conn = get_db()
    cursor = get_cursor(conn)
    cursor.execute('DELETE FROM weekly_leaderboard')
    conn.commit()
    conn.close()
    return jsonify({"success": True, "message": "All leaderboard data cleared"})

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "database": "postgresql",
        "auth_configured": bool(TWITTER_CLIENT_ID)
    })

# Initialize database on startup
if DATABASE_URL:
    try:
        init_db()
    except Exception as e:
        print(f"⚠️ Database initialization error: {e}")

if __name__ == "__main__":
    print("\n" + "="*60)
    print("🚀 Magicblob API with PostgreSQL Database")
    print("="*60)
    
    if not TWITTER_CLIENT_ID:
        print("⚠️  Twitter OAuth not configured!")
        print("   Set TWITTER_CLIENT_ID environment variable")
    else:
        print("✅ Twitter OAuth configured")
    
    if not DATABASE_URL:
        print("⚠️  DATABASE_URL not configured!")
    else:
        print("✅ PostgreSQL database configured")
    
    print(f"\n📍 API running at: http://localhost:8000")
    print("="*60 + "\n")
    
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)), debug=False)
