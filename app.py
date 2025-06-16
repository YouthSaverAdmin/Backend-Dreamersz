from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import re
import random
from datetime import datetime, timedelta
from bson import ObjectId
import pytz
import bcrypt
from flask import Flask, Response, request, jsonify
from pymongo import MongoClient
from flask_cors import CORS
import os
import smtplib
import string
from dotenv import load_dotenv
import jwt
import datetime
import secrets
import jwt
from flask import request, jsonify
from gridfs import GridFS
from werkzeug.utils import secure_filename
from bson import ObjectId
load_dotenv()  # Load .env variables if you use a .env file

app = Flask(__name__)
CORS(
    app,
    supports_credentials=True,  # Important for cookies
    origins=["http://localhost:5173", "https://dreamersuniqueinc.vercel.app"]  # Your frontend URL
)

# MongoDB setup
MONGO_URI = f"mongodb+srv://genaisukiro17:{os.getenv('DB_PASSWORD')}@ecommerce.lgsvlzl.mongodb.net/"
DB_NAME = "dreamersz"
client = MongoClient(MONGO_URI, tlsAllowInvalidCertificates=True)
db = client[DB_NAME]
verifications = db['email_verifications']
orders = db["orders"]
users = db['users']
JWT_SECRET = os.getenv('JWT_SECRET', 'your_super_secret_key_here')
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour token expiration
fs = GridFS(db)
# Email server config
MAIL_SERVER = os.getenv("MAIL_SERVER")
MAIL_PORT = int(os.getenv("MAIL_PORT", 587))
MAIL_USE_TLS = os.getenv("MAIL_USE_TLS", "True").lower() in ["true", "1", "yes"]
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_DEFAULT_SENDER = os.getenv("MAIL_DEFAULT_SENDER") or MAIL_USERNAME

is_production = os.getenv("FLASK_ENV") == "production"

print("JWT module path:", getattr(jwt, '__file__', 'Not found'))
print("Has encode():", hasattr(jwt, 'encode'))


# Regex and password validation
EMAIL_REGEX = re.compile(r"[^@]+@[^@]+\.[^@]+")

def is_valid_password(pw):
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$', pw))

def generate_verification_code(length=6):
    return ''.join(random.choices(string.digits, k=length))

@app.route('/api/send-verification-email/', methods=['POST'])
def send_verification_email():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    if not email:
        return jsonify({"error": "Email is required"}), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({"error": "Invalid email format"}), 400

    code = generate_verification_code()
    expires_at = now = datetime.datetime.utcnow() + timedelta(minutes=10)  # code expires in 10 minutes

    subject = "Your Verification Code"
    body = f"Your verification code is: {code}\n\nThis code expires in 10 minutes."

    message = f"From: {MAIL_DEFAULT_SENDER}\r\nTo: {email}\r\nSubject: {subject}\r\n\r\n{body}"

    try:
        server = smtplib.SMTP(MAIL_SERVER, MAIL_PORT)
        if MAIL_USE_TLS:
            server.starttls()
        server.login(MAIL_USERNAME, MAIL_PASSWORD)
        server.sendmail(MAIL_DEFAULT_SENDER, email, message)
        server.quit()

        # Upsert verification code and expiry time in DB
        verifications.update_one(
            {'email': email},
            {'$set': {'code': code, 'expires_at': expires_at}},
            upsert=True
        )

        return jsonify({"message": "Verification email sent"})
    except Exception as e:
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500

@app.route('/verify-code-and-register/', methods=['POST'])
def verify_code_and_register():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    name = data.get('name', '').strip()
    password = data.get('password', '')
    code = data.get('code', '').strip()
    timezone_str = data.get('timezone', 'UTC').strip()

    if not (email and name and password and code and timezone_str):
        return jsonify({'error': 'All fields including timezone are required'}), 400

    if not EMAIL_REGEX.match(email):
        return jsonify({'error': 'Invalid email format'}), 400

    if not is_valid_password(password):
        return jsonify({
            'error': 'Password must be at least 8 characters, include uppercase, lowercase, and a number.'
        }), 400

    record = verifications.find_one({'email': email})
    if not record:
        return jsonify({'error': 'No verification code found. Please request a new one.'}), 400

    if record.get('code') != code:
        return jsonify({'error': 'Invalid verification code'}), 400

    if datetime.datetime.utcnow() > record.get('expires_at'):
        verifications.delete_one({'email': email})
        return jsonify({'error': 'Verification code expired. Please request a new one.'}), 400

    if users.find_one({'email': email}):
        return jsonify({'error': 'User with this email already exists'}), 400

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        user_tz = pytz.timezone(timezone_str)
    except Exception:
        user_tz = pytz.utc

    now_utc = datetime.datetime.utcnow().replace(tzinfo=pytz.utc)
    now_local = now_utc.astimezone(user_tz)

    users.insert_one({
        'name': name,
        'email': email,
        'password': hashed_pw.decode('utf-8'),
        'created_at': now_local.isoformat(),
        'timezone': timezone_str
    })

    # Remove verification record after successful registration
    verifications.delete_one({'email': email})

    print(f"[MongoDB] Registered new user: {email}")
    return jsonify({'message': 'Registration complete'})

@app.route('/api/login/', methods=['POST'])
def login():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = users.find_one({'email': email})
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401

    stored_hash = user.get('password').encode('utf-8')
    if not bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        return jsonify({'error': 'Invalid email or password'}), 401

    payload = {
        'user_id': str(user['_id']),
        'email': user['email'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    response = jsonify({
        'message': 'Login successful',
        'token': token,
        'user': {
            'name': user.get('name'),
            'email': user.get('email'),
            'timezone': user.get('timezone')
        }
    })

    # Optional: Set JWT in HttpOnly cookie
    response.set_cookie(
        'access_token',
        token,
        httponly=True,
        secure=True,      # <-- this requires HTTPS!
        max_age=JWT_EXP_DELTA_SECONDS,
        samesite='None'
)

    return response

@app.route('/api/check-auth/', methods=['GET'])
def check_auth():
    token = None

    # Try to get token from HttpOnly cookie 'access_token'
    if 'access_token' in request.cookies:
        token = request.cookies.get('access_token')

    # Or alternatively from Authorization header (Bearer token)
    # auth_header = request.headers.get('Authorization')
    # if auth_header and auth_header.startswith('Bearer '):
    #     token = auth_header.split(' ')[1]

    if not token:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('user_id')
        email = payload.get('email')

        # Optionally, check if user still exists in DB (recommended)
        user = users.find_one({'_id': ObjectId(user_id)})
        if not user:
            return jsonify({'error': 'User not found'}), 404

        return jsonify({
            'message': 'Authenticated',
            'user': {
                'name': user.get('name'),
                'email': user.get('email'),
                'timezone': user.get('timezone'),
            }
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/logout/', methods=['POST'])
def logout():
    response = jsonify({'message': 'Logged out'})
    # Clear the cookie by setting it to empty and expired
    response.set_cookie('access_token', '', expires=0, httponly=True, secure=True, samesite='None')
    return response

def get_current_user_id():
    token = request.cookies.get('access_token')
    if not token:
        return None
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload.get('user_id')
    except:
        return None


@app.route('/api/store', methods=['GET'])
def get_store():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    store = db.stores.find_one({'owner_id': user_id})
    if not store:
        return jsonify({'store': None}), 200
    # Convert ObjectId to string if needed
    store['_id'] = str(store['_id'])
    return jsonify({'store': store}), 200

@app.route('/api/store', methods=['POST'])
def create_store():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    data = request.get_json()
    name = data.get('name')
    if not name:
        return jsonify({'error': 'Store name is required'}), 400
    # Check if user already has store
    if db.stores.find_one({'owner_id': user_id}):
        return jsonify({'error': 'Store already exists'}), 400

    store = {'name': name, 'owner_id': user_id}
    result = db.stores.insert_one(store)
    store['_id'] = str(result.inserted_id)
    return jsonify({'store': store}), 201

@app.route('/api/items', methods=['POST'])
def create_item():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    # Parse form-data
    name = request.form.get('name')
    price = request.form.get('price')
    store_id = request.form.get('store_id')
    description = request.form.get('description', '')  # Optional, defaults to empty string
    image_file = request.files.get('image')

    if not all([name, price, store_id, image_file]):
        return jsonify({'error': 'Missing fields'}), 400

    # Validate store ownership
    store = db.stores.find_one({'_id': ObjectId(store_id), 'owner_id': user_id})
    if not store:
        return jsonify({'error': 'Invalid store or unauthorized'}), 403

    # Save image to GridFS
    image_data = image_file.read()
    filename = secure_filename(image_file.filename)
    content_type = image_file.content_type

    file_id = fs.put(image_data, filename=filename, content_type=content_type)

    # Create item document
    item = {
        'name': name,
        'price': float(price),
        'description': description,
        'store_id': ObjectId(store_id),
        'image_file_id': file_id
    }

    result = db.items.insert_one(item)

    item['_id'] = str(result.inserted_id)
    item['store_id'] = str(item['store_id'])
    item['image_file_id'] = str(file_id)

    return jsonify({'item': item}), 201



@app.route('/uploads/<file_id>')
def serve_image(file_id):
    try:
        file = fs.get(ObjectId(file_id))
        return Response(file.read(), mimetype=file.content_type)
    except Exception as e:
        print(f"Error serving image: {e}")
        return "Image not found", 404



@app.route("/api/my-items")
def get_my_items():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Find all store IDs owned by user
    stores = list(db.stores.find({"owner_id": user_id}, {"_id": 1}))
    store_ids = [store["_id"] for store in stores]

    # Find items in those stores
    items = list(db.items.find({"store_id": {"$in": store_ids}}))

    # Convert ObjectIds to strings for JSON serialization
    for item in items:
        item["_id"] = str(item["_id"])
        item["store_id"] = str(item["store_id"])
        item["image_file_id"] = str(item.get("image_file_id", ""))
    
    return jsonify({"items": items})

@app.route('/api/items/<item_id>', methods=['DELETE'])
def delete_item(item_id):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    item = db.items.find_one({'_id': ObjectId(item_id)})
    if not item:
        return jsonify({'error': 'Item not found'}), 404

    # Optional: check ownership via store owner
    store = db.stores.find_one({'_id': ObjectId(item['store_id'])})
    if not store or store['owner_id'] != user_id:
        return jsonify({'error': 'Unauthorized'}), 403

    db.items.delete_one({'_id': ObjectId(item_id)})
    return jsonify({'message': 'Item deleted successfully'}), 200

def convert_objectid_to_str(doc):
    if isinstance(doc, list):
        return [convert_objectid_to_str(i) for i in doc]
    if isinstance(doc, dict):
        return {k: convert_objectid_to_str(v) for k, v in doc.items()}
    if isinstance(doc, ObjectId):
        return str(doc)
    return doc

@app.route('/api/items/<item_id>', methods=['PUT'])
def update_item(item_id):
    try:
        data = request.get_json()
        print(f"Received update for {item_id}: {data}")

        result = db.items.update_one(
            {'_id': ObjectId(item_id)},
            {'$set': {'name': data.get('name'), 'price': data.get('price')}}
        )

        if result.modified_count == 0:
            return jsonify({'error': 'No item updated'}), 404

        updated_item = db.items.find_one({'_id': ObjectId(item_id)})

        updated_item = convert_objectid_to_str(updated_item)  # Convert all ObjectIds

        return jsonify({'updatedItem': updated_item}), 200

    except Exception as e:
        print(f"Error updating item: {e}")
        return jsonify({'error': 'Internal server error'}), 500



@app.route("/api/show-product")
def show_product():
    items = list(db.items.find({}))
    valid_items = []

    for item in items:
        item = convert_objectid(item)
        image_file_id = item.get("image_file_id")

        if image_file_id:
            try:
                file_obj_id = ObjectId(image_file_id)
                # Use filter dict in fs.exists
                exists = fs.exists({"_id": file_obj_id})
                if not exists:
                    item["image_file_id"] = None
            except Exception:
                # In case invalid ObjectId
                item["image_file_id"] = None
        else:
            item["image_file_id"] = None
        
        valid_items.append(item)

    return jsonify({"items": valid_items})


@app.route("/api/product/<product_id>")
def get_product_detail(product_id):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        product_obj_id = ObjectId(product_id)
    except Exception:
        return jsonify({"error": "Invalid product ID"}), 400

    try:
        product = db.items.find_one({"_id": product_obj_id})
        if not product:
            return jsonify({"error": "Product not found"}), 404

        product = convert_objectid(product)

        # Validate image file id
        image_file_id = product.get("image_file_id")
        if image_file_id:
            try:
                file_obj_id = ObjectId(image_file_id)
                if not fs.exists({"_id": file_obj_id}):
                    product["image_file_id"] = None
            except Exception:
                product["image_file_id"] = None
        else:
            product["image_file_id"] = None

        store = None
        owner_email = None

        if "store_id" in product:
            try:
                store_obj_id = ObjectId(product["store_id"])
                store = db.stores.find_one({"_id": store_obj_id})
                if store:
                    store = convert_objectid(store)

                    owner_id_str = store.get("owner_id")
                    if owner_id_str:
                        # Owner ID stored as string, convert to ObjectId
                        try:
                            owner_obj_id = ObjectId(owner_id_str)
                            owner = db.users.find_one({"_id": owner_obj_id})
                            if owner:
                                owner_email = owner.get("email")
                        except Exception:
                            owner_email = None
            except Exception:
                store = None

        response = {
            "product": product,
            "store": store,
            "user_email": owner_email or "N/A",
        }

        return jsonify(response)

    except Exception as e:
        print(f"Error fetching product detail: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/image/<file_id>")
def serve_image_file(file_id):
    try:
        file_obj_id = ObjectId(file_id)
        file = fs.get(file_obj_id)
        # Use deprecated warning safe mimetype access
        mimetype = getattr(file, 'content_type', 'application/octet-stream')
        return Response(file.read(), mimetype=mimetype)
    except Exception as e:
        return jsonify({"error": "Image not found"}), 404

def convert_objectids_to_str(obj):
    """Recursively convert ObjectId fields in a dict to strings."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, ObjectId):
                obj[k] = str(v)
            elif isinstance(v, dict):
                convert_objectids_to_str(v)
            elif isinstance(v, list):
                for item in v:
                    convert_objectids_to_str(item)
    elif isinstance(obj, list):
        for item in obj:
            convert_objectids_to_str(item)
    return obj

@app.route('/api/cart', methods=['GET'])
def get_cart():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    try:
        pipeline = [
            {"$match": {"user_id": user_id}},
            {
                "$lookup": {
                    "from": "items",
                    "localField": "product_id",
                    "foreignField": "_id",
                    "as": "product"
                }
            },
            {"$unwind": {"path": "$product", "preserveNullAndEmptyArrays": True}},
            {
                "$lookup": {
                    "from": "stores",
                    "localField": "product.store_id",
                    "foreignField": "_id",
                    "as": "store"
                }
            },
            {"$unwind": {"path": "$store", "preserveNullAndEmptyArrays": True}},
            {
                "$addFields": {
                    "product.store": "$store"
                }
            },
            {
                "$project": {
                    "store": 0
                }
            }
        ]

        cart_items = list(db.cart.aggregate(pipeline))

        # Recursively convert all ObjectIds to strings
        cart_items = convert_objectid(cart_items)

        return jsonify({'cart': cart_items})

    except Exception as e:
        print("Error fetching cart:", e)
        return jsonify({'error': 'Failed to fetch cart'}), 500
    
@app.route('/api/cart', methods=['POST'])
def add_to_cart():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    user = db.users.find_one({"_id": ObjectId(user_id)})
    if not user:
        return jsonify({'error': 'User not found'}), 404

    user_email = user.get('email')
    data = request.json or {}
    product_id = data.get('product_id')
    quantity = data.get('quantity', 1)

    if not product_id:
        return jsonify({'error': 'Product ID required'}), 400

    try:
        product_obj_id = ObjectId(product_id)
    except Exception:
        return jsonify({'error': 'Invalid Product ID'}), 400

    try:
        quantity = int(quantity)
        if quantity <= 0:
            raise ValueError()
    except ValueError:
        return jsonify({'error': 'Quantity must be a positive integer'}), 400

    product = db.items.find_one({'_id': product_obj_id})
    if not product:
        return jsonify({'error': 'Product not found'}), 404

    # 🔁 Fix: Get store email from stores collection using owner_id
    store_name = "Unknown Store"
    store_owner_email = "N/A"
    store_id = product.get("store_id")

    if store_id:
        try:
            store = db.stores.find_one({'_id': ObjectId(store_id)})
            if store:
                store_name = store.get('name', 'Unknown Store')
                owner_id = store.get('owner_id')

                if owner_id:
                    if not isinstance(owner_id, ObjectId):
                        owner_id = ObjectId(owner_id)

                    owner = db.users.find_one({'_id': owner_id})
                    if owner:
                        store_owner_email = owner.get('email', 'N/A')
        except Exception as e:
            print(f"[ERROR] Fetching store or owner email failed: {e}")

    # Prevent user from adding their own product to cart
    if store_owner_email != "N/A" and store_owner_email == user_email:
        return jsonify({'error': "You can't add your own product to the cart."}), 403

    # Insert or update cart item
    existing_item = db.cart.find_one({'user_id': user_id, 'product_id': product_obj_id})
    if existing_item:
        db.cart.update_one(
            {'_id': existing_item['_id']},
            {'$inc': {'quantity': quantity}}
        )
    else:
        db.cart.insert_one({
            'user_id': user_id,
            'product_id': product_obj_id,
            'quantity': quantity,
            'product_name': product.get('name'),
            'price': product.get('price'),
            'description': product.get('description', ''),
            'store_name': store_name,
            'store_owner_email': store_owner_email,
            'image_file_id': product.get('image_file_id'),
            'added_at': datetime.datetime.utcnow(),
        })

    return jsonify({'message': 'Added to cart'}), 201

@app.route('/api/cart/<cart_item_id>', methods=['DELETE'])
def remove_from_cart(cart_item_id):
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401

    result = db.cart.delete_one({'_id': ObjectId(cart_item_id), 'user_id': user_id})

    if result.deleted_count == 0:
        return jsonify({'error': 'Item not found or unauthorized'}), 404

    return jsonify({'message': 'Item removed from cart'})

def convert_objectid(obj):
    if isinstance(obj, list):
        return [convert_objectid(i) for i in obj]
    if isinstance(obj, dict):
        return {k: convert_objectid(v) for k, v in obj.items()}
    if isinstance(obj, ObjectId):
        return str(obj)
    return obj


@app.route('/api/forgot-password/', methods=['POST'])
def forgot_password():
    data = request.json or {}
    email = data.get('email', '').strip().lower()

    if not email:
        return jsonify({'error': 'Email is required'}), 400
    if not EMAIL_REGEX.match(email):
        return jsonify({'error': 'Invalid email format'}), 400

    user = users.find_one({'email': email})
    # Don't reveal if email exists or not
    if not user:
        return jsonify({'message': 'If that email exists, a reset link has been sent.'})

    reset_token = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.utcnow() + timedelta(hours=1)

    db.password_resets.update_one(
        {'email': email},
        {'$set': {'token': reset_token, 'expires_at': expires_at}},
        upsert=True
    )

    reset_link = f"https://backend-dreamersz.onrender.com/ResetPassword?token={reset_token}"

    # Compose email using MIMEText for better formatting
    msg = MIMEMultipart()
    msg['From'] = MAIL_DEFAULT_SENDER
    msg['To'] = email
    msg['Subject'] = "Password Reset Request"

    body = f"""Hi {user.get('name')},

To reset your password, click the link below:
{reset_link}

This link expires in 1 hour.

If you did not request a password reset, please ignore this email.
"""
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            if MAIL_USE_TLS:
                server.starttls()
            server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        # Log the exception for debugging (optional)
        print(f"Failed to send reset email: {e}")
        return jsonify({'error': f'Failed to send reset email: {str(e)}'}), 500

    return jsonify({'message': 'If that email exists, a reset link has been sent.'})

@app.route('/api/reset-password/', methods=['POST'])
def reset_password():
    data = request.json or {}
    token = data.get('token', '').strip()
    new_password = data.get('password', '')

    if not token or not new_password:
        return jsonify({'error': 'Token and new password are required'}), 400

    if not is_valid_password(new_password):
        return jsonify({
            'error': 'Password must be at least 8 characters, include uppercase, lowercase, and a number.'
        }), 400

    record = db.password_resets.find_one({'token': token})
    if not record:
        return jsonify({'error': 'Invalid or expired token'}), 400

    if datetime.datetime.utcnow() > record.get('expires_at'):
        db.password_resets.delete_one({'token': token})
        return jsonify({'error': 'Token expired. Please request a new password reset.'}), 400

    email = record['email']
    user = users.find_one({'email': email})
    if not user:
        db.password_resets.delete_one({'token': token})
        return jsonify({'error': 'User not found'}), 400

    hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    users.update_one({'email': email}, {'$set': {'password': hashed_pw.decode('utf-8')}})

    # Remove used reset token to prevent reuse
    db.password_resets.delete_one({'token': token})

    return jsonify({'message': 'Password has been reset successfully.'}), 200


@app.route("/api/simulate-stripe-payment", methods=["POST"])
def simulate_payment():
    data = request.get_json()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    card = data.get("cardNumber", "").strip().replace(" ", "")
    expiry = data.get("expiry", "").strip()
    cvc = data.get("cvc", "").strip()
    amount = data.get("amount")
    cart = data.get("cart", [])

    if not all([name, email, card, expiry, cvc, amount, cart]):
        return jsonify({
            "success": False,
            "message": "All fields are required, including amount and cart."
        }), 400

    if card != "4242424242424242":
        return jsonify({
            "success": False,
            "message": "Card declined. Use 4242 4242 4242 4242."
        }), 400

    # Prepare items summary
    purchased_items = []
    for item in cart:
        product = item.get("product", {})
        purchased_items.append({
            "product_name": product.get("name", "Unknown"),
            "store_name": product.get("store_name", "N/A"),
            "store_owner_email": product.get("store_owner_email", "N/A"),
            "price": product.get("price", 0),
            "quantity": item.get("quantity", 1),
        })

    # Create order
    order = {
        "customer_name": name,
        "customer_email": email,
        "card_last4": card[-4:],
        "amount": int(float(amount) * 100),  # store in cents
        "status": "success",
        "timestamp": datetime.datetime.utcnow(),
        "items": purchased_items  # Add product info here
    }

    result = orders.insert_one(order)

    return jsonify({"success": True, "order_id": str(result.inserted_id)}), 200


@app.route("/api/my-orders", methods=["GET"])
def get_my_orders():
    user_id = get_current_user_id()
    if not user_id:
        return jsonify({"orders": [], "message": "Not authenticated"}), 401

    user = users.find_one({"_id": ObjectId(user_id)})
    if not user or "email" not in user:
        return jsonify({"orders": [], "message": "User not found"}), 404

    email = user["email"]
    user_orders = list(orders.find({"customer_email": email}))

    for order in user_orders:
        order["_id"] = str(order["_id"])
        if isinstance(order.get("timestamp"), datetime.datetime):
            order["timestamp"] = order["timestamp"].isoformat()

    return jsonify({"orders": user_orders}), 200
if __name__ == '__main__':
    app.run(debug=True)
