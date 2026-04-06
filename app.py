from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_mail import Mail, Message
from models import db, User, Product, Order,OTP,Review,Cart,Payment,OrderItem,OrderStatusHistory
from werkzeug.utils import secure_filename
import os
import uuid
import random
import string
import jwt
import datetime
from datetime import datetime, timedelta
import base64
import requests
from functools import wraps
from flask_cors import cross_origin
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash

# Initialize Flask App
app = Flask(__name__)
application = app

CORS(app)

app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ecommerce.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Configure Flask-Mail with your custom domain SMTP settings
app.config['MAIL_SERVER'] = 'mail.imoflames.co.ke'  # Your outgoing server
app.config['MAIL_PORT'] = 465                       # SMTP port for SSL
app.config['MAIL_USE_SSL'] = True                   # Use SSL instead of TLS
app.config['MAIL_USE_TLS'] = False                  # Disable TLS when using SSL
app.config['MAIL_USERNAME'] = 'admin@imoflames.co.ke'  # Your email username
app.config['MAIL_PASSWORD'] = 'imoflames#12x#'    # Your email account password
app.config['MAIL_DEFAULT_SENDER'] = 'admin@imoflames.co.ke'  # Default sender address
ADMIN_SECRET = os.environ.get('ADMIN_SECRET', 'reagan#12x#')  # Default for development only
YOUMING_API_URL = os.environ.get('YOUMING_API_URL', 'https://sandbox.youmingtech.com/api/v1')
YOUMING_CONSUMER_KEY = "3AfKIkFsNqxAAavpyAddQ3FWt3EgGwIp3G4fNxGOoY4B7rPG"
YOUMING_CONSUMER_SECRET = "ze41GyDlmDLkQM9FE6OAVY2bgLNrKwsGcbUEN0kkA93KZK3CcN6GXI8HUCOyHMC5"
YOUMING_SHORTCODE = os.environ.get('YOUMING_SHORTCODE', '174379')
YOUMING_CALLBACK_URL = os.environ.get('YOUMING_CALLBACK_URL', 'https://your-domain.com')  # ADD THIS LINE
mail = Mail(app)

# Initialize DB
db.init_app(app)
migrate = Migrate(app, db)

# Create tables
with app.app_context():
    db.create_all()

# Allowed file types
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Update your token_required decorator at the top of your app.py

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Allow OPTIONS requests to pass through for CORS preflight
        if request.method == 'OPTIONS':
            return jsonify({}), 200
            
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            return jsonify({'message': f'Token error: {str(e)}'}), 401
            
        return f(current_user, *args, **kwargs)
    return decorated

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'message': 'Admin access required!'}), 403
        return f(current_user, *args, **kwargs)
    return decorated

# Email notification function (FIXED - only one definition)
def send_order_notification(user, product, order, email=None):
    try:
        recipient = email or user.email
        print(f"Sending user email to: {recipient}")
        
        # Email to user
        user_msg = Message("Order Confirmation", recipients=[recipient])
        user_msg.body = f"Thank you {user.username} for your order! Your order for {product.name} has been placed and is being processed."
        user_msg.sender = app.config['MAIL_DEFAULT_SENDER']
        mail.send(user_msg)
        print("User email sent successfully")

        # Email to all admins
        admins = User.query.filter_by(is_admin=True).all()
        if admins:
            admin_emails = [admin.email for admin in admins]
            print(f"Sending admin emails to: {admin_emails}")
            
            admin_msg = Message("New Order Placed", recipients=admin_emails)
            admin_msg.body = f"""
            A new order has been placed by {user.username} for {product.name}.
            Order ID: {order.id}
            Product: {product.name}
            Price: ksh{product.price}
            Phone Number: {order.phone_number}
            Email: {order.email}
            Location: {order.location}
            """
            admin_msg.sender = app.config['MAIL_DEFAULT_SENDER']
            mail.send(admin_msg)
            print("Admin emails sent successfully")
        else:
            print("No admin users found!")
            
    except Exception as e:
        print(f"Failed to send email notifications: {str(e)}")
        import traceback
        traceback.print_exc()
        # Don't raise the exception here to avoid breaking the main flow
@app.route('/request_reset_password', methods=['POST'])
def request_reset_password():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    otp = generate_otp()
    store_otp(email, otp)

   
    username = user.username  
    msg = Message('Password Reset Request', sender='noreply@yourapp.com', recipients=[email])
    msg.body = f"""
    Hello, {username}

    Here's the verification code to reset your password:

    {otp}

    To reset your password, enter this verification code when prompted.

    This code will expire in 5 minutes.

    If you did not request this password reset, please ignore this email.
    """
    mail.send(msg)

    return jsonify({"message": "OTP sent to your email"}), 200
@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')
    new_password = data.get('new_password')

    if not email or not otp or not new_password:
        return jsonify({"error": "Missing email, OTP or new password"}), 400

    otp_entry = OTP.query.filter_by(email=email).first()
    if not otp_entry:
        return jsonify({"error": "OTP not requested"}), 404

    if datetime.utcnow() > otp_entry.expiry:
        return jsonify({"error": "OTP expired"}), 400

    if otp_entry.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    user.password_hash = generate_password_hash(new_password)
    db.session.commit()
    db.session.delete(otp_entry)
    db.session.commit()

    return jsonify({"message": "Password reset successfully"}), 200

@app.route('/get_user_role_by_email', methods=['POST'])
def get_user_role_by_email():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    return jsonify({'role': user.role}), 200
 
 
@app.route('/check_email_exists', methods=['POST'])
def check_email_exists():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'message': 'Email exists'}), 200
    else:
        return jsonify({'error': 'Email not found'}), 404

@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({"error": "Email and OTP are required"}), 400

    otp_entry = OTP.query.filter_by(email=email).first()

    if not otp_entry:
        return jsonify({"error": "OTP not requested or does not exist"}), 404

    if datetime.utcnow() > otp_entry.expiry:
        return jsonify({
            "error": "OTP expired",
            "message": "Did time run out? Request a new OTP.",
            "request_new_otp": True
        }), 400

    if otp_entry.otp != otp:
        return jsonify({"error": "Invalid OTP"}), 400

   
    return jsonify({"message": "OTP is valid"}), 200

@app.route('/request_new_otp', methods=['POST'])
def request_new_otp():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"error": "Email is required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({"error": "User with this email does not exist"}), 404

    otp = generate_otp()
    store_otp(email, otp)

    
    username = user.username  
    msg = Message('Password Reset Request', sender='noreply@yourapp.com', recipients=[email])
    msg.body = f"""
    Hello, {username}

    Here's the verification code to reset your password:

    {otp}

    To reset your password, enter this verification code when prompted.

    This code will expire in 5 minutes.

    If you did not request this password reset, please ignore this email.
    """
    mail.send(msg)

    return jsonify({"message": "New OTP sent to your email"}), 200

def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def store_otp(email, otp):
    expiry = datetime.utcnow() + timedelta(minutes=5)
    otp_entry = OTP.query.filter_by(email=email).first()
    if otp_entry:
        otp_entry.otp = otp
        otp_entry.expiry = expiry
    else:
        otp_entry = OTP(email=email, otp=otp, expiry=expiry)
        db.session.add(otp_entry)
    db.session.commit()
# Add these endpoints to your app.py

# Get user profile
@app.route('/api/user/profile', methods=['GET', 'PUT'])
@token_required
def user_profile(current_user):
    if request.method == 'GET':
        return jsonify(current_user.to_dict()), 200
    
    elif request.method == 'PUT':
        data = request.get_json()
        current_user.username = data.get('username', current_user.username)
        current_user.email = data.get('email', current_user.email)
        current_user.profile_picture = data.get('profile_picture', current_user.profile_picture)
        db.session.commit()
        return jsonify(current_user.to_dict()), 200

# Update profile picture
@app.route('/api/user/profile-picture', methods=['PUT'])
@token_required
def update_profile_picture(current_user):
    if 'profile_picture' not in request.files:
        return jsonify({'message': 'No file uploaded'}), 400
    
    file = request.files['profile_picture']
    if file:
        filename = secure_filename(f"profile_{current_user.id}_{datetime.now().timestamp()}.{file.filename.split('.')[-1]}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        current_user.profile_picture = filename
        db.session.commit()
        return jsonify({'profile_picture': filename}), 200
    
    return jsonify({'message': 'Upload failed'}), 400

# Change password
@app.route('/api/user/change-password', methods=['PUT'])
@token_required
def change_password(current_user):
    data = request.get_json()
    if not current_user.check_password(data.get('current_password')):
        return jsonify({'message': 'Current password is incorrect'}), 401
    
    current_user.set_password(data.get('new_password'))
    db.session.commit()
    return jsonify({'message': 'Password changed successfully'}), 200
# In app.py - Add this endpoint for creating orders

@app.route('/api/orders', methods=['POST'])
@token_required
def create_order(current_user):
    """Create a new order with multiple items"""
    try:
        data = request.get_json()
        
        # Extract data
        items = data.get('items', [])
        total_amount = data.get('total_amount')
        phone_number = data.get('phone_number')
        email = data.get('email')
        location = data.get('location')
        delivery_notes = data.get('delivery_notes', '')
        payment_method = data.get('payment_method', 'cash')
        
        # Validate required fields
        if not items or len(items) == 0:
            return jsonify({'message': 'No items in order'}), 400
        
        if not total_amount or not phone_number or not email or not location:
            return jsonify({'message': 'Missing required fields'}), 400
        
        # Create the order
        order = Order(
            user_id=current_user.id,
            phone_number=phone_number,
            email=email,
            location=location,
            delivery_notes=delivery_notes,
            total_amount=total_amount,
            status='pending',
            timestamp=datetime.utcnow()
        )
        db.session.add(order)
        db.session.flush()
        
        # Track unique sellers to notify
        sellers_notified = set()
        
        # Create order items and notify sellers
        for item in items:
            product_id = item.get('product_id')
            quantity = item.get('quantity', 1)
            price = item.get('price', 0)
            
            # Verify product exists
            product = Product.query.get(product_id)
            if not product:
                db.session.rollback()
                return jsonify({'message': f'Product {product_id} not found'}), 404
            
            order_item = OrderItem(
                order_id=order.id,
                product_id=product_id,
                quantity=quantity,
                price=price
            )
            db.session.add(order_item)
            
            # Notify seller (product owner) if not already notified
            seller_id = product.user_id
            if seller_id not in sellers_notified and seller_id != current_user.id:
                sellers_notified.add(seller_id)
                seller = User.query.get(seller_id)
                if seller and seller.email:
                    send_order_to_seller(order, seller.email)
        
        # Create payment record
        payment = Payment(
            amount=total_amount,
            status='completed' if payment_method == 'cash' else 'pending',
            payment_method=payment_method,
            order_id=order.id,
            user_id=current_user.id,
            phone_number=phone_number if payment_method == 'mpesa' else None,
            transaction_id=f"{payment_method.upper()}_{uuid.uuid4().hex[:8]}"
        )
        db.session.add(payment)
        
        # Clear user's cart
        Cart.query.filter_by(user_id=current_user.id).delete()
        
        db.session.commit()
        
        # Send email to customer
        send_order_email_notification(current_user, order, payment)
        
        return jsonify({
            'message': 'Order placed successfully!',
            'order': order.to_dict(),
            'payment': payment.to_dict()
        }), 201
        
    except Exception as e:
        print(f"Error creating order: {e}")
        db.session.rollback()
        return jsonify({'message': f'Error creating order: {str(e)}'}), 500
# Add these after your existing code

@app.route('/api/orders', methods=['GET'])
@token_required
def get_orders(current_user):
    """Get all orders for current user"""
    try:
        orders = Order.query.filter_by(user_id=current_user.id).order_by(Order.timestamp.desc()).all()
        
        orders_list = []
        for order in orders:
            order_dict = {
                "id": order.id,
                "user_id": order.user_id,
                "phone_number": order.phone_number,
                "email": order.email,
                "location": order.location,
                "delivery_notes": order.delivery_notes,
                "total_amount": order.total_amount,
                "status": order.status,
                "timestamp": order.timestamp.isoformat() if order.timestamp else None,
                "items": []
            }
            
            # Add order items
            for item in order.items:
                order_dict["items"].append({
                    "id": item.id,
                    "product_id": item.product_id,
                    "quantity": item.quantity,
                    "price": item.price,
                    "product": item.product.to_dict() if item.product else None
                })
            
            # Add payment info
            payment = Payment.query.filter_by(order_id=order.id).first()
            if payment:
                order_dict["payment"] = {
                    "id": payment.id,
                    "amount": payment.amount,
                    "status": payment.status,
                    "payment_method": payment.payment_method,
                    "transaction_id": payment.transaction_id,
                    "mpesa_receipt_number": payment.mpesa_receipt_number
                }
            
            orders_list.append(order_dict)
        
        return jsonify(orders_list), 200
        
    except Exception as e:
        print(f"Error fetching orders: {e}")
        return jsonify({'message': 'Error fetching orders'}), 500


@app.route('/api/orders/<int:order_id>', methods=['GET'])
@token_required
def get_single_order(current_user, order_id):
    """Get a single order by ID"""
    try:
        order = Order.query.filter_by(id=order_id, user_id=current_user.id).first()
        if not order:
            return jsonify({'message': 'Order not found'}), 404
        
        order_dict = {
            "id": order.id,
            "user_id": order.user_id,
            "phone_number": order.phone_number,
            "email": order.email,
            "location": order.location,
            "delivery_notes": order.delivery_notes,
            "total_amount": order.total_amount,
            "status": order.status,
            "timestamp": order.timestamp.isoformat() if order.timestamp else None,
            "items": []
        }
        
        # Add order items
        for item in order.items:
            order_dict["items"].append({
                "id": item.id,
                "product_id": item.product_id,
                "quantity": item.quantity,
                "price": item.price,
                "product": item.product.to_dict() if item.product else None
            })
        
        # Add payment info
        payment = Payment.query.filter_by(order_id=order.id).first()
        if payment:
            order_dict["payment"] = {
                "id": payment.id,
                "amount": payment.amount,
                "status": payment.status,
                "payment_method": payment.payment_method,
                "transaction_id": payment.transaction_id,
                "mpesa_receipt_number": payment.mpesa_receipt_number
            }
        
        return jsonify(order_dict), 200
        
    except Exception as e:
        print(f"Error fetching order: {e}")
        return jsonify({'message': 'Error fetching order'}), 500




def send_order_email_notification(user, order, payment):
    """Send order confirmation email to customer and admin"""
    try:
        # Get all items in the order
        items_text = ""
        total = 0
        for item in order.items:
            product_name = item.product.name if item.product else f"Product #{item.product_id}"
            item_total = item.price * item.quantity
            items_text += f"- {product_name} x {item.quantity} = KES {item_total:,.2f}\n"
            total += item_total
        
        # Email to customer
        customer_msg = Message(
            f"Order Confirmation - Order #{order.id}",
            recipients=[order.email]
        )
        customer_msg.body = f"""
Dear {user.username},

Thank you for your order! Your order has been received and is being processed.

Order Details:
--------------
Order ID: #{order.id}
Date: {order.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Payment Method: {payment.payment_method.upper()}
Payment Status: {payment.status.upper()}
Transaction ID: {payment.transaction_id}

Items Ordered:
{items_text}
Total Amount: KES {total:,.2f}

Delivery Information:
-------------------
Location: {order.location}
Phone: {order.phone_number}
Email: {order.email}
Delivery Notes: {order.delivery_notes or 'None'}

You can track your order status in your account dashboard.

Thank you for shopping with ImoFlames!
"""
        customer_msg.sender = app.config['MAIL_DEFAULT_SENDER']
        mail.send(customer_msg)
        print(f"Order confirmation email sent to {order.email}")

        # Email to all admins
        admins = User.query.filter_by(is_admin=True).all()
        if admins:
            admin_emails = [admin.email for admin in admins]
            admin_msg = Message(
                f"New Order Placed - Order #{order.id}",
                recipients=admin_emails
            )
            admin_msg.body = f"""
New Order Alert!

Order ID: #{order.id}
Customer: {user.username} ({order.email})
Phone: {order.phone_number}
Date: {order.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Payment Method: {payment.payment_method.upper()}
Payment Status: {payment.status.upper()}
Transaction ID: {payment.transaction_id}

Items:
{items_text}
Total Amount: KES {total:,.2f}

Delivery Location: {order.location}
Delivery Notes: {order.delivery_notes or 'None'}

Please process this order promptly.
"""
            admin_msg.sender = app.config['MAIL_DEFAULT_SENDER']
            mail.send(admin_msg)
            print(f"Order notification email sent to admins: {admin_emails}")
            
    except Exception as e:
        print(f"Email error: {e}")
        import traceback
        traceback.print_exc()
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400

    # Check if this is an admin registration attempt
    is_admin = False
    admin_secret = data.get('admin_secret')
    
    if admin_secret:
        # Verify admin secret on backend (hidden from frontend)
        if admin_secret == ADMIN_SECRET:
            is_admin = True
        else:
            return jsonify({'message': 'Invalid admin authorization code'}), 403

    # Optional: Check if regular user is trying to create admin without secret
    if data.get('is_admin') and not admin_secret:
        return jsonify({'message': 'Admin authorization required'}), 403

    # Check if admin registration is allowed (optional: only existing admins can create admins)
    if is_admin:
        # Optional: Check if requesting user is admin (if using JWT)
        requesting_user = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
            try:
                decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
                requesting_user = User.query.get(decoded['user_id'])
                # Only existing admins can create other admins
                if not requesting_user or not requesting_user.is_admin:
                    return jsonify({'message': 'Only existing administrators can create new admin accounts'}), 403
            except:
                return jsonify({'message': 'Admin authorization required'}), 403

    new_user = User(
        username=data['username'],
        email=data['email'],
        is_admin=is_admin  # This will be True only if secret matched
    )
    new_user.set_password(data['password'])

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

from sqlalchemy import or_
# In your Flask backend
@app.route('/api/auth/google', methods=['POST', 'OPTIONS'])
def google_auth():
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    
    try:
        data = request.get_json()
        print("Received Google auth data:", data)  # For debugging
        
        google_id = data.get('googleId')
        email = data.get('email')
        username = data.get('username')
        picture = data.get('picture')
        
        if not google_id or not email:
            return jsonify({'message': 'Missing required fields'}), 400
        
        # Check if user exists by email
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Create new user with Google authentication
            # Check if username already exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                # If username exists, append a random number
                base_username = username
                counter = 1
                while User.query.filter_by(username=username).first():
                    username = f"{base_username}{counter}"
                    counter += 1
            
            user = User(
                username=username,
                email=email,
                google_id=google_id,
                profile_picture=picture,
                is_verified=True,  # Google verified the email
                can_upload=False,  # Default to False, admin can change later
                is_admin=False
            )
            db.session.add(user)
            db.session.commit()
            print(f"Created new user: {user.username} (ID: {user.id})")
        else:
            # Update existing user's Google ID if not already set
            if not user.google_id:
                user.google_id = google_id
            # Update profile picture if provided and user doesn't have one
            if picture and not user.profile_picture:
                user.profile_picture = picture
            db.session.commit()
            print(f"Existing user logged in: {user.username} (ID: {user.id})")
        
        # Generate JWT token
        token = jwt.encode({
            'user_id': user.id,
            'email': user.email,
            'username': user.username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        # Return user data
        response_data = {
            'token': token,
            'user': user.to_dict()
        }
        
        return jsonify(response_data), 200
        
    except Exception as e:
        print(f"Error in google_auth: {str(e)}")
        db.session.rollback()
        return jsonify({'message': f'Authentication error: {str(e)}'}), 500
    
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('identifier') or not data.get('password'):
        return jsonify({'message': 'Missing username/email or password'}), 400

    identifier = data['identifier']

    # Allow login with either username OR email
    user = User.query.filter(
        or_(User.username == identifier, User.email == identifier)
    ).first()

    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm='HS256')

    return jsonify({
        'token': token,
        'user': user.to_dict()
    })

@app.route('/api/products', methods=['GET'])
def get_products():
    # Extract query parameters
    search = request.args.get('search', '').strip().lower() if request.args.get('search') else None
    min_price = request.args.get('min')
    max_price = request.args.get('max')
    category = request.args.get('category', '').strip().lower() if request.args.get('category') else None
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 20))

    # Build filters
    filters = []
    if search:
        search_term = f"%{search.replace(' ', '%')}%"
        filters.append(Product.name.ilike(search_term))
    if min_price:
        try:
            filters.append(Product.price >= float(min_price))
        except ValueError:
            pass  # Ignore invalid min_price
    if max_price:
        try:
            filters.append(Product.price <= float(max_price))
        except ValueError:
            pass  # Ignore invalid max_price
    if category:
        filters.append(Product.category.ilike(f"%{category}%"))

    # Handle Authorization header safely
    current_user = None
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        try:
            token = auth_header.split(" ")[1]
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(decoded['user_id'])
        except jwt.ExpiredSignatureError:
            print("Token expired")
        except jwt.InvalidTokenError:
            print("Invalid token")
        except Exception as e:
            print(f"Error decoding token: {str(e)}")

    # Pagination
    paginated_products = Product.query.filter(*filters).paginate(page=page, per_page=limit, error_out=False)
    products = paginated_products.items
    total_pages = paginated_products.pages
    total_products = paginated_products.total

    return jsonify({
        'products': [product.to_dict() for product in products],
        'totalPages': total_pages,
        'totalProducts': total_products,
    })

@app.route('/api/test-email', methods=['POST'])
def test_email():
    data = request.get_json()
    recipient_email = data.get('email')

    if not recipient_email:
        return jsonify({'message': 'Recipient email is required'}), 400

    try:
        # Create a test email message
        msg = Message("Test Email", recipients=[recipient_email])
        msg.body = "This is a test email to verify the email configuration."
        msg.sender = app.config['MAIL_DEFAULT_SENDER']

        # Send the email
        mail.send(msg)

        return jsonify({'message': 'Test email sent successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Failed to send test email: {str(e)}'}), 500

@app.route('/api/buy/<int:product_id>', methods=['POST'])
@token_required
def buy_product(current_user, product_id):
    data = request.get_json()
    product = Product.query.get_or_404(product_id)

    if product.user_id == current_user.id:
        return jsonify({'message': 'You cannot buy your own product'}), 400

    phone_number = data.get('phone_number')
    email = data.get('email')
    location = data.get('location')

    if not phone_number or not email or not location:
        return jsonify({'message': 'Missing required order details'}), 400

    print(f"Order email: {email}")
    print(f"Current user email: {current_user.email}")

    new_order = Order(
        product_id=product_id,
        user_id=current_user.id,
        phone_number=phone_number,
        email=email,
        location=location,
        status='pending'
    )

    db.session.add(new_order)
    db.session.commit()

    try:
        print("Calling send_order_notification...")
        send_order_notification(current_user, product, new_order, email=email)
    except Exception as e:
        print(f"Failed to send email notifications: {str(e)}")

    return jsonify({'message': 'Order placed successfully'}), 200

@app.route('/api/products', methods=['POST'])
@token_required
def create_product(current_user):
    if not current_user.is_admin and not current_user.can_upload:
        return jsonify({
            'message': 'You do not have permission to upload products',
            'reason': 'admin_approval_required',
            'hint': 'Contact admin for upload permission'
        }), 403

    if 'images' not in request.files:
        return jsonify({'message': 'No image file provided'}), 400

    files = request.files.getlist('images')
    if len(files) == 0:
        return jsonify({'message': 'No selected image files'}), 400

    data = request.form
    if not data.get('name'):
        return jsonify({'message': 'Product name is required'}), 400

    if not data.get('price') or not data.get('price').replace('.', '', 1).isdigit():
        return jsonify({'message': 'Valid price is required (e.g., 500)'}), 400

    # Validate first image
    main_file = files[0]
    if not allowed_file(main_file.filename):
        return jsonify({'message': 'Invalid main image file type. Use: png, jpg, jpeg, gif'}), 400

    try:
        filename = secure_filename(main_file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        main_file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))

        # Save extra images
        extra_image_paths = []
        for file in files[1:]:
            if file and allowed_file(file.filename):
                ext_filename = secure_filename(file.filename)
                ext_unique = f"{uuid.uuid4().hex}_{ext_filename}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], ext_unique))
                extra_image_paths.append(ext_unique)

        new_product = Product(
            name=data['name'],
            description=data.get('description', ''),
            price=float(data['price']),
            image_path=unique_filename,
            extra_images=",".join(extra_image_paths),
            category=data.get('category', ''),
            is_approved=current_user.is_admin,
            user_id=current_user.id
        )

        db.session.add(new_product)
        db.session.commit()

        return jsonify(new_product.to_dict()), 201

    except Exception as e:
        db.session.rollback()
        print("Upload error:", str(e))
        return jsonify({'message': 'Failed to upload product. Please try again later.'}), 500

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(current_user, product_id):
    # Check if product exists
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    
    # Check if user has permission (owner or admin)
    if product.user_id != current_user.id and not current_user.is_admin:
        return jsonify({
            'message': 'You do not have permission to update this product',
            'reason': 'ownership_required',
            'hint': 'Only product owner or admin can update'
        }), 403
    
    data = request.form
    
    # Validate required fields
    if not data.get('name'):
        return jsonify({'message': 'Product name is required'}), 400
    
    if not data.get('price') or not data.get('price').replace('.', '', 1).isdigit():
        return jsonify({'message': 'Valid price is required (e.g., 500)'}), 400
    
    try:
        # Handle main image update if provided
        if 'images' in request.files:
            files = request.files.getlist('images')
            if files and files[0]:
                main_file = files[0]
                if not allowed_file(main_file.filename):
                    return jsonify({'message': 'Invalid main image file type. Use: png, jpg, jpeg, gif'}), 400
                
                # Delete old main image
                if product.image_path:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image_path))
                    except OSError:
                        pass
                
                # Save new main image
                filename = secure_filename(main_file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                main_file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                product.image_path = unique_filename
        
        # Handle extra images update if provided
        if 'images' in request.files and len(request.files.getlist('images')) > 1:
            files = request.files.getlist('images')[1:]
            if files:
                # Delete old extra images
                if product.extra_images:
                    for old_image in product.extra_images.split(','):
                        try:
                            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], old_image))
                        except OSError:
                            pass
                
                # Save new extra images
                extra_image_paths = []
                for file in files:
                    if file and allowed_file(file.filename):
                        ext_filename = secure_filename(file.filename)
                        ext_unique = f"{uuid.uuid4().hex}_{ext_filename}"
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], ext_unique))
                        extra_image_paths.append(ext_unique)
                product.extra_images = ",".join(extra_image_paths)
        
        # Update product fields
        product.name = data['name']
        product.description = data.get('description', product.description)
        product.price = float(data['price'])
        product.category = data.get('category', product.category)
        
        # If admin is updating, maintain the approval status
        if not current_user.is_admin:
            product.is_approved = False  # Require re-approval if edited by non-admin
        
        db.session.commit()
        
        return jsonify(product.to_dict()), 200
    
    except Exception as e:
        db.session.rollback()
        print("Update error:", str(e))
        return jsonify({'message': 'Failed to update product. Please try again later.'}), 500
# In app.py - Add these cart endpoints

@app.route('/api/cart', methods=['GET'])
@token_required
def get_cart(current_user):
    """Get user's cart"""
    try:
        cart_items = Cart.query.filter_by(user_id=current_user.id).all()
        return jsonify([item.to_dict() for item in cart_items]), 200
    except Exception as e:
        print(f"Error fetching cart: {e}")
        return jsonify({'message': 'Error fetching cart'}), 500

@app.route('/api/cart/add/<int:product_id>', methods=['POST'])
@token_required
def add_to_cart(current_user, product_id):
    """Add product to cart"""
    try:
        data = request.get_json() or {}
        quantity = data.get('quantity', 1)
        
        # Check if product exists
        product = db.session.get(Product, product_id)
        if not product:
            return jsonify({'message': 'Product not found'}), 404
        
        # Check if item already in cart
        cart_item = Cart.query.filter_by(
            user_id=current_user.id,
            product_id=product_id
        ).first()
        
        if cart_item:
            # Update quantity
            cart_item.quantity += quantity
            db.session.commit()
            return jsonify({'message': 'Cart updated successfully'}), 200
        else:
            # Add new item
            cart_item = Cart(
                user_id=current_user.id,
                product_id=product_id,
                quantity=quantity
            )
            db.session.add(cart_item)
            db.session.commit()
            return jsonify({'message': 'Product added to cart'}), 201
            
    except Exception as e:
        print(f"Error adding to cart: {e}")
        db.session.rollback()
        return jsonify({'message': f'Error: {str(e)}'}), 500

@app.route('/api/cart/update/<int:item_id>', methods=['PUT'])
@token_required
def update_cart_item(current_user, item_id):
    """Update cart item quantity"""
    try:
        data = request.get_json()
        new_quantity = data.get('quantity')
        
        if not new_quantity or new_quantity < 1:
            return jsonify({'message': 'Invalid quantity'}), 400
        
        cart_item = Cart.query.filter_by(id=item_id, user_id=current_user.id).first()
        if not cart_item:
            return jsonify({'message': 'Cart item not found'}), 404
        
        cart_item.quantity = new_quantity
        db.session.commit()
        
        return jsonify({'message': 'Cart updated successfully'}), 200
        
    except Exception as e:
        print(f"Error updating cart: {e}")
        db.session.rollback()
        return jsonify({'message': 'Error updating cart'}), 500

@app.route('/api/cart/remove/<int:item_id>', methods=['DELETE'])
@token_required
def remove_cart_item(current_user, item_id):
    """Remove item from cart"""
    try:
        cart_item = Cart.query.filter_by(id=item_id, user_id=current_user.id).first()
        if not cart_item:
            return jsonify({'message': 'Cart item not found'}), 404
        
        db.session.delete(cart_item)
        db.session.commit()
        
        return jsonify({'message': 'Item removed from cart'}), 200
        
    except Exception as e:
        print(f"Error removing cart item: {e}")
        db.session.rollback()
        return jsonify({'message': 'Error removing item'}), 500
@app.route('/api/cart/checkout', methods=['POST'])
@token_required
def checkout(current_user):
    try:
        data = request.get_json()
        phone_number = data.get('phone_number')
        email = data.get('email')
        location = data.get('location')

        if not phone_number or not email or not location:
            return jsonify({'message': 'Missing required order details'}), 400

        print(f"Checkout email: {email}")
        print(f"Current user email: {current_user.email}")

        pending_orders = Order.query.filter_by(user_id=current_user.id, status='pending').all()
        if not pending_orders:
            return jsonify({'message': 'No items in cart to checkout'}), 400

        for order in pending_orders:
            order.status = 'completed'
            order.phone_number = phone_number
            order.email = email
            order.location = location

        db.session.commit()

        try:
            for order in pending_orders:
                product = Product.query.get(order.product_id)
                print(f"Sending notification for order ID: {order.id}")
                send_order_notification(current_user, product, order, email=email)
        except Exception as e:
            print(f"Failed to send email notifications: {str(e)}")

        return jsonify({'message': 'Checkout successful'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': f'Failed to checkout: {str(e)}'}), 500



@app.route('/api/cart/remove/<int:product_id>', methods=['DELETE'])
@token_required
def remove_from_cart(current_user, product_id):
    # Check if the order exists and is pending
    order = Order.query.filter_by(
        user_id=current_user.id,
        product_id=product_id,
        status='pending'
    ).first()

    if not order:
        return jsonify({'message': 'Product not found in cart'}), 404

    db.session.delete(order)
    db.session.commit()

    return jsonify({'message': 'Removed from cart'}), 200

@app.route('/api/cart')
@token_required
def view_cart(current_user):
    orders = Order.query.filter_by(user_id=current_user.id, status='pending').all()
    product_ids = [o.product_id for o in orders]
    if not product_ids:
        return jsonify([])  # Empty cart

    products = Product.query.filter(Product.id.in_(product_ids)).all()
    return jsonify([p.to_dict() for p in products])

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    product = Product.query.get_or_404(product_id)

    # Authorization check
    if not (product.user_id == current_user.id or current_user.is_admin):
        return jsonify({'message': 'Unauthorized: You can only delete your own products'}), 403

    try:
        # Get all images to delete
        all_images = [product.image_path]
        if product.extra_images:
            all_images.extend(product.extra_images.split(','))
        
        # Delete files from filesystem
        for image in all_images:
            if image:  # Skip empty strings
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], image)
                if os.path.exists(file_path):
                    os.remove(file_path)
        
        # Delete from database
        db.session.delete(product)
        db.session.commit()
        
        return jsonify({'message': 'Product and associated images deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Error deleting product {product_id}: {str(e)}')
        return jsonify({
            'message': 'Failed to delete product',
            'error': str(e)
        }), 500

@app.route('/api/users/me')
@token_required
def get_current_user(current_user):
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'is_admin': current_user.is_admin
    })

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@token_required
@admin_required
def approve_product(current_user, product_id):
    product = Product.query.get_or_404(product_id)
    product.is_approved = True
    db.session.commit()
    print(f"Product approved: {product.to_dict()}")
    return jsonify(product.to_dict())
# In app.py, ensure you have this endpoint for getting a single product

@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    """Get a single product by ID"""
    try:
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'message': 'Product not found'}), 404
        
        # Check if product is approved (if you have approval system)
        if not product.is_approved and not current_user_has_permission():
            return jsonify({'message': 'Product not available'}), 403
        
        return jsonify(product.to_dict()), 200
    except Exception as e:
        print(f"Error fetching product: {e}")
        return jsonify({'message': 'Error fetching product'}), 500

# Helper function to check if user has permission to view unapproved products
def current_user_has_permission():
    """Check if current user has admin or uploader permissions"""
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return False
    
    try:
        token = auth_header.split(' ')[1]
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        user = User.query.get(payload['user_id'])
        return user and (user.is_admin or user.can_upload)
    except:
        return False
@app.route('/api/my-products')
@token_required
def my_products(current_user):
    # Option 1: Show all products the user has bought
    orders = Order.query.filter_by(user_id=current_user.id, status='completed').all()
    bought_product_ids = [o.product_id for o in orders if o.product_id]

    # Option 2: Show all products the user has uploaded (approved or not)
    sold_products = Product.query.filter_by(user_id=current_user.id).all()

    # Combine both lists
    bought_products = Product.query.filter(
        Product.id.in_(bought_product_ids)
    ).all()

    # Return both sets as separate sections if needed
    return jsonify({
        'purchased': [p.to_dict() for p in bought_products],
        'uploaded': [p.to_dict() for p in sold_products]
    }), 200

@app.route('/api/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/users/grant-upload/<int:user_id>', methods=['PUT'])
@token_required
@admin_required
def grant_upload_permission(current_user, user_id):
    user = User.query.get_or_404(user_id)
    user.can_upload = not user.can_upload  # Toggle permission
    db.session.commit()
    return jsonify({
        'message': 'Upload permission updated',
        'can_upload': user.can_upload,
        'username': user.username
    }), 200



@app.route('/api/contact-us', methods=['POST'])
def contact_us():
    data = request.get_json()

    # Extract necessary information from the request
    product_info = data.get('product_info', {})
    user_phone_number = data.get('phone_number')
    user_email = data.get('email')
    user_message = data.get('message')
    supplier_info = data.get('supplier_info', {})

    # Validate the data
    if not user_phone_number or not user_email or not user_message:
        return jsonify({'message': 'Missing required fields'}), 400

    # Create an email message
    subject = "New Contact Us Submission"
    body = f"""
    You have received a new contact form submission:

    User Phone Number: {user_phone_number}
    User Email: {user_email}
    User Message: {user_message}

    Product Info:
    {product_info}

    Supplier Info:
    {supplier_info}
    """

    # Get all admin emails
    admins = User.query.filter_by(is_admin=True).all()
    admin_emails = [admin.email for admin in admins]

    try:
        # Send the email to all admins
        msg = Message(subject, recipients=admin_emails)
        msg.body = body
        msg.sender = app.config['MAIL_DEFAULT_SENDER']
        mail.send(msg)

        return jsonify({'message': 'Contact form submitted successfully'}), 200
    except Exception as e:
        return jsonify({'message': f'Failed to send contact form: {str(e)}'}), 500
@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    """Serve uploaded files from the uploads folder"""
    upload_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
    return send_from_directory(upload_folder, filename)

# Also ensure your upload folder exists
if not os.path.exists('uploads'):
    os.makedirs('uploads')

# In app.py - Add review endpoints

@app.route('/api/products/<int:product_id>/reviews', methods=['GET'])
def get_product_reviews(product_id):
    """Get all reviews for a product"""
    reviews = Review.query.filter_by(product_id=product_id).order_by(Review.created_at.desc()).all()
    return jsonify([review.to_dict() for review in reviews]), 200

@app.route('/api/products/<int:product_id>/reviews', methods=['POST'])
@token_required
def create_review(current_user, product_id):
    """Create a review for a product"""
    data = request.get_json()
    rating = data.get('rating')
    comment = data.get('comment')
    
    if not rating or rating < 1 or rating > 5:
        return jsonify({'message': 'Rating must be between 1 and 5'}), 400
    
    # Check if user already reviewed this product
    existing_review = Review.query.filter_by(
        product_id=product_id, 
        user_id=current_user.id
    ).first()
    
    if existing_review:
        # Update existing review
        existing_review.rating = rating
        existing_review.comment = comment
        db.session.commit()
        return jsonify(existing_review.to_dict()), 200
    
    # Create new review
    review = Review(
        product_id=product_id,
        user_id=current_user.id,
        user_name=current_user.username,
        rating=rating,
        comment=comment
    )
    db.session.add(review)
    db.session.commit()
    
    return jsonify(review.to_dict()), 201

# Update the review endpoints to handle PUT and DELETE
@app.route('/api/products/<int:product_id>/reviews', methods=['POST', 'PUT', 'DELETE'])
@token_required
def manage_reviews(current_user, product_id):
    # POST - Create review
    if request.method == 'POST':
        data = request.get_json()
        rating = data.get('rating')
        comment = data.get('comment')
        
        if not rating or rating < 1 or rating > 5:
            return jsonify({'message': 'Rating must be between 1 and 5'}), 400
        
        # Check if user already reviewed
        existing = Review.query.filter_by(product_id=product_id, user_id=current_user.id).first()
        if existing:
            return jsonify({'message': 'You have already reviewed this product'}), 400
        
        review = Review(
            product_id=product_id,
            user_id=current_user.id,
            user_name=current_user.username,
            rating=rating,
            comment=comment
        )
        db.session.add(review)
        db.session.commit()
        return jsonify(review.to_dict()), 201
    
    # PUT - Update review
    elif request.method == 'PUT':
        data = request.get_json()
        rating = data.get('rating')
        comment = data.get('comment')
        
        review = Review.query.filter_by(product_id=product_id, user_id=current_user.id).first()
        if not review:
            return jsonify({'message': 'Review not found'}), 404
        
        if rating:
            review.rating = rating
        if comment is not None:
            review.comment = comment
        
        db.session.commit()
        return jsonify(review.to_dict()), 200
    
    # DELETE - Delete review
    elif request.method == 'DELETE':
        review = Review.query.filter_by(product_id=product_id, user_id=current_user.id).first()
        if not review:
            return jsonify({'message': 'Review not found'}), 404
        
        db.session.delete(review)
        db.session.commit()
        return jsonify({'message': 'Review deleted successfully'}), 200

# app.py - Using Safaricom M-Pesa Sandbox

import requests
import base64
import json
from datetime import datetime
import os
# app.py - Complete with working M-Pesa STK Push and email notifications

# ... (keep all your existing imports and configurations)

# ============ M-Pesa Configuration ============
# Set this to True to send real STK pushes, False for simulation
USE_REAL_MPESA = True

# Safaricom M-Pesa Sandbox Configuration
MPESA_CONSUMER_KEY = "3AfKIkFsNqxAAavpyAddQ3FWt3EgGwIp3G4fNxGOoY4B7rPG"
MPESA_CONSUMER_SECRET = "ze41GyDlmDLkQM9FE6OAVY2bgLNrKwsGcbUEN0kkA93KZK3CcN6GXI8HUCOyHMC5"
MPESA_PASSKEY = "bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919"
MPESA_SHORTCODE = "174379"

# For local testing, use ngrok: ngrok http 5000
# Then set this to your ngrok URL (e.g., https://abc123.ngrok.io)
MPESA_CALLBACK_URL = os.environ.get('MPESA_CALLBACK_URL', 'https://abc123.ngrok.io')

# Safaricom Sandbox URLs
MPESA_AUTH_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
MPESA_STK_PUSH_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
MPESA_STK_QUERY_URL = "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query"

def get_mpesa_token():
    """Get M-Pesa API token from Safaricom sandbox with timeout"""
    try:
        credentials = f"{MPESA_CONSUMER_KEY}:{MPESA_CONSUMER_SECRET}"
        encoded_credentials = base64.b64encode(credentials.encode()).decode()
        
        headers = {
            'Authorization': f'Basic {encoded_credentials}',
            'Content-Type': 'application/json'
        }
        
        # Add timeout and retry
        import time
        for attempt in range(2):
            try:
                response = requests.get(MPESA_AUTH_URL, headers=headers, timeout=15)
                
                if response.status_code == 200:
                    result = response.json()
                    return result.get('access_token')
                else:
                    print(f"Token attempt {attempt + 1} failed: {response.status_code}")
                    if attempt == 0:
                        time.sleep(2)
                        continue
                    return None
                    
            except requests.exceptions.Timeout:
                print(f"Token attempt {attempt + 1} timed out")
                if attempt == 0:
                    time.sleep(2)
                    continue
                return None
            except Exception as e:
                print(f"Token error: {e}")
                if attempt == 0:
                    time.sleep(2)
                    continue
                return None
                
        return None
            
    except Exception as e:
        print(f"M-Pesa token error: {e}")
        return None

def generate_mpesa_password():
    """Generate the password for M-Pesa API"""
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    password_str = f"{MPESA_SHORTCODE}{MPESA_PASSKEY}{timestamp}"
    password = base64.b64encode(password_str.encode()).decode()
    return password, timestamp

def send_order_email_notification(user, order, payment):
    """Send order confirmation email to customer and admin"""
    try:
        # Get all items in the order
        items = []
        total = 0
        for item in order.items:
            items.append(f"- {item.product.name} x {item.quantity} = KES {item.price * item.quantity}")
            total += item.price * item.quantity
        
        items_text = "\n".join(items)
        
        # Email to customer
        customer_msg = Message(
            f"Order Confirmation - Order #{order.id}",
            recipients=[order.email]
        )
        customer_msg.body = f"""
Dear {user.username},

Thank you for your order! Your order has been received and is being processed.

Order Details:
--------------
Order ID: #{order.id}
Date: {order.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Payment Method: {payment.payment_method.upper()}
Payment Status: {payment.status.upper()}
Transaction ID: {payment.transaction_id}

Items Ordered:
{items_text}

Total Amount: KES {total:,.2f}

Delivery Information:
-------------------
Location: {order.location}
Phone: {order.phone_number}
Email: {order.email}
Delivery Notes: {order.delivery_notes or 'None'}

You can track your order status in your account dashboard.

Thank you for shopping with ImoFlames!
"""
        customer_msg.sender = app.config['MAIL_DEFAULT_SENDER']
        mail.send(customer_msg)
        print(f"Order confirmation email sent to {order.email}")

        # Email to admin
        admins = User.query.filter_by(is_admin=True).all()
        if admins:
            admin_emails = [admin.email for admin in admins]
            admin_msg = Message(
                f"New Order Placed - Order #{order.id}",
                recipients=admin_emails
            )
            admin_msg.body = f"""
New Order Alert!

Order ID: #{order.id}
Customer: {user.username} ({order.email})
Phone: {order.phone_number}
Date: {order.timestamp.strftime('%Y-%m-%d %H:%M:%S')}
Payment Method: {payment.payment_method.upper()}
Payment Status: {payment.status.upper()}
Transaction ID: {payment.transaction_id}

Items:
{items_text}

Total Amount: KES {total:,.2f}

Delivery Location: {order.location}
Delivery Notes: {order.delivery_notes or 'None'}

Please process this order promptly.
"""
            admin_msg.sender = app.config['MAIL_DEFAULT_SENDER']
            mail.send(admin_msg)
            print(f"Order notification email sent to admins: {admin_emails}")
            
    except Exception as e:
        print(f"Email error: {e}")
        import traceback
        traceback.print_exc()

def process_simulation_payment(current_user, phone_number, amount, order_data):
    """Process payment in simulation mode (bypasses real M-Pesa)"""
    try:
        import uuid
        
        print(f"SIMULATION MODE: Processing payment for {phone_number} - Amount: {amount}")
        
        # Create completed payment record
        payment = Payment(
            amount=amount,
            transaction_id=f"SIM_{uuid.uuid4().hex[:8]}",
            checkout_request_id=f"SIM_REQ_{uuid.uuid4().hex[:8]}",
            status='completed',
            payment_method='mpesa',
            user_id=current_user.id,
            phone_number=phone_number,
            mpesa_receipt_number=f"SIM_{uuid.uuid4().hex[:10]}"
        )
        db.session.add(payment)
        db.session.flush()
        
        # Create order
        order = Order(
            user_id=current_user.id,
            phone_number=phone_number,
            email=order_data.get('delivery_details', {}).get('email'),
            location=order_data.get('delivery_details', {}).get('location'),
            delivery_notes=order_data.get('delivery_details', {}).get('delivery_notes', ''),
            total_amount=amount,
            status='pending'
        )
        db.session.add(order)
        db.session.flush()
        
        # Create order items
        for item in order_data.get('items', []):
            order_item = OrderItem(
                order_id=order.id,
                product_id=item.get('product_id'),
                quantity=item.get('quantity', 1),
                price=item.get('price', 0)
            )
            db.session.add(order_item)
        
        # Link payment to order
        payment.order_id = order.id
        
        # Clear user's cart
        Cart.query.filter_by(user_id=current_user.id).delete()
        
        db.session.commit()
        
        # Send email notifications
        send_order_email_notification(current_user, order, payment)
        
        return jsonify({
            'checkout_request_id': payment.checkout_request_id,
            'message': 'Order placed successfully! (Simulation Mode)',
            'simulated': True,
            'order_id': order.id
        }), 200
        
    except Exception as e:
        print(f"Simulation error: {e}")
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

# Replace your mpesa_stkpush function with this updated version

@app.route('/api/mpesa/stkpush', methods=['POST'])
@token_required
def mpesa_stkpush(current_user):
    """Initiate M-Pesa STK Push - Creates order immediately"""
    try:
        data = request.get_json()
        phone_number = data.get('phone_number')
        amount = data.get('amount')
        order_data = data.get('order_data')
        
        if not phone_number:
            return jsonify({'message': 'Phone number is required'}), 400
        
        # Format phone number
        phone_number = str(phone_number).strip()
        if phone_number.startswith('0'):
            phone_number = '254' + phone_number[1:]
        elif phone_number.startswith('+'):
            phone_number = phone_number[1:]
        
        # Create order IMMEDIATELY
        order = Order(
            user_id=current_user.id,
            phone_number=phone_number,
            email=order_data.get('delivery_details', {}).get('email'),
            location=order_data.get('delivery_details', {}).get('location'),
            delivery_notes=order_data.get('delivery_details', {}).get('delivery_notes', ''),
            total_amount=amount,
            status='pending'
        )
        db.session.add(order)
        db.session.flush()
        
        # Create order items
        for item in order_data.get('items', []):
            order_item = OrderItem(
                order_id=order.id,
                product_id=item.get('product_id'),
                quantity=item.get('quantity', 1),
                price=item.get('price', 0)
            )
            db.session.add(order_item)
        
        # Create payment record
        payment = Payment(
            amount=amount,
            transaction_id=f"MPESA_{int(datetime.now().timestamp())}",
            checkout_request_id=f"REQ_{int(datetime.now().timestamp())}_{current_user.id}",
            status='pending',
            payment_method='mpesa',
            order_id=order.id,
            user_id=current_user.id,
            phone_number=phone_number
        )
        db.session.add(payment)
        
        # Clear user's cart
        Cart.query.filter_by(user_id=current_user.id).delete()
        
        db.session.commit()
        
        # Send email notifications immediately
        send_order_email_notification(current_user, order, payment)
        
        # Try to send STK Push (optional - don't fail if it doesn't work)
        try:
            token = get_mpesa_token()
            if token:
                password, timestamp = generate_mpesa_password()
                headers = {
                    'Authorization': f'Bearer {token}',
                    'Content-Type': 'application/json'
                }
                callback_url = f"{MPESA_CALLBACK_URL}/api/mpesa/callback"
                payload = {
                    'BusinessShortCode': MPESA_SHORTCODE,
                    'Password': password,
                    'Timestamp': timestamp,
                    'TransactionType': 'CustomerPayBillOnline',
                    'Amount': int(amount),
                    'PartyA': phone_number,
                    'PartyB': MPESA_SHORTCODE,
                    'PhoneNumber': phone_number,
                    'CallBackURL': callback_url,
                    'AccountReference': f'Order_{order.id}',
                    'TransactionDesc': 'ImoFlames Order Payment'
                }
                response = requests.post(MPESA_STK_PUSH_URL, json=payload, headers=headers, timeout=30)
                result = response.json()
                if response.status_code == 200 and result.get('ResponseCode') == '0':
                    payment.checkout_request_id = result.get('CheckoutRequestID')
                    payment.transaction_id = result.get('CheckoutRequestID')
                    db.session.commit()
        except Exception as e:
            print(f"STK Push error (non-critical): {e}")
            # Don't fail - order is already saved
        
        # Always return success with order_id
        return jsonify({
            'checkout_request_id': payment.checkout_request_id,
            'order_id': order.id,
            'message': 'Order placed successfully!',
            'simulated': True
        }), 200
        
    except Exception as e:
        print(f"M-Pesa STK Push error: {e}")
        db.session.rollback()
        return jsonify({'message': str(e)}), 500

@app.route('/api/mpesa/callback', methods=['POST'])
def mpesa_callback():
    """M-Pesa Callback endpoint - Updates payment and order status"""
    try:
        data = request.get_json()
        print(f"M-Pesa Callback received: {json.dumps(data, indent=2)}")
        
        stk_callback = data.get('Body', {}).get('stkCallback', {})
        result_code = stk_callback.get('ResultCode')
        checkout_request_id = stk_callback.get('CheckoutRequestID')
        
        # Find payment by checkout_request_id
        payment = Payment.query.filter_by(checkout_request_id=checkout_request_id).first()
        
        if not payment:
            print(f"Payment not found for checkout_request_id: {checkout_request_id}")
            return jsonify({'ResultCode': 1, 'ResultDesc': 'Payment not found'}), 404
        
        if result_code == '0':  # Payment successful
            # Extract payment details
            callback_metadata = stk_callback.get('CallbackMetadata', {})
            items = callback_metadata.get('Item', [])
            
            mpesa_receipt_number = None
            for item in items:
                if item.get('Name') == 'MpesaReceiptNumber':
                    mpesa_receipt_number = item.get('Value')
            
            # Update payment
            payment.status = 'completed'
            payment.mpesa_receipt_number = mpesa_receipt_number
            payment.transaction_id = mpesa_receipt_number
            
            # Update order status
            if payment.order:
                payment.order.status = 'completed'
            
            db.session.commit()
            print(f"Payment completed for order #{payment.order_id}: {mpesa_receipt_number}")
            
        elif result_code == '1037':  # User cancelled
            payment.status = 'failed'
            if payment.order:
                payment.order.status = 'cancelled'
            db.session.commit()
            print(f"Payment cancelled by user")
        else:
            payment.status = 'failed'
            if payment.order:
                payment.order.status = 'failed'
            db.session.commit()
            print(f"Payment failed: {result_code}")
        
        return jsonify({'ResultCode': 0, 'ResultDesc': 'Success'}), 200
        
    except Exception as e:
        print(f"Callback error: {e}")
        db.session.rollback()
        return jsonify({'ResultCode': 1, 'ResultDesc': str(e)}), 500

@app.route('/api/mpesa/status/<checkout_request_id>', methods=['GET'])
@token_required
def check_mpesa_status(current_user, checkout_request_id):
    """Check M-Pesa payment status"""
    try:
        # Find payment by checkout_request_id or transaction_id
        payment = Payment.query.filter(
            (Payment.checkout_request_id == checkout_request_id) |
            (Payment.transaction_id == checkout_request_id)
        ).first()
        
        if not payment:
            return jsonify({'status': 'not_found'}), 404
        
        # Get order details
        order = Order.query.get(payment.order_id) if payment.order_id else None
        
        return jsonify({
            'status': payment.status,
            'transaction_id': payment.transaction_id,
            'amount': payment.amount,
            'mpesa_receipt_number': payment.mpesa_receipt_number,
            'order_id': payment.order_id,
            'order_status': order.status if order else None,
            'simulated': payment.transaction_id and payment.transaction_id.startswith(('SIM_', 'FALLBACK_', 'ERROR_'))
        }), 200
        
    except Exception as e:
        print(f"Error checking payment: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500
# Add this endpoint to manually send order email if needed
@app.route('/api/order/email/<int:order_id>', methods=['POST'])
@token_required
def resend_order_email(current_user, order_id):
    """Resend order confirmation email"""
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({'message': 'Order not found'}), 404
        
        payment = Payment.query.filter_by(order_id=order.id).first()
        if not payment:
            return jsonify({'message': 'Payment not found'}), 404
        
        user = User.query.get(order.user_id)
        
        send_order_email_notification(user, order, payment)
        
        return jsonify({'message': 'Email sent successfully'}), 200
        
    except Exception as e:
        print(f"Error sending email: {e}")
        return jsonify({'message': str(e)}), 500
# Add these endpoints to your app.py

def send_order_status_email(order, old_status, new_status, note, recipient_email):
    """Send email notification when order status changes"""
    try:
        # Get order items
        items_text = ""
        total = 0
        for item in order.items:
            product_name = item.product.name if item.product else f"Product #{item.product_id}"
            item_total = item.price * item.quantity
            items_text += f"- {product_name} x {item.quantity} = KES {item_total:,.2f}\n"
            total += item_total
        
        status_messages = {
            'processing': 'Your order is now being processed by the seller.',
            'shipped': 'Your order has been shipped and is on its way!',
            'delivered': 'Your order has been delivered. Thank you for shopping with us!',
            'cancelled': 'Your order has been cancelled.'
        }
        
        message = status_messages.get(new_status, f'Your order status has been updated to {new_status}.')
        if note:
            message += f"\n\nNote from seller: {note}"
        
        msg = Message(
            f"Order #{order.id} Status Update - {new_status.upper()}",
            recipients=[recipient_email]
        )
        msg.body = f"""
Dear Customer,

Your order status has been updated.

Order ID: #{order.id}
Previous Status: {old_status.upper()}
New Status: {new_status.upper()}

{message}

Order Details:
{items_text}
Total Amount: KES {total:,.2f}

Delivery Location: {order.location}

Track your order in your account dashboard.

Thank you for shopping with ImoFlames!
"""
        msg.sender = app.config['MAIL_DEFAULT_SENDER']
        mail.send(msg)
        print(f"Status update email sent to {recipient_email}")
        
    except Exception as e:
        print(f"Error sending status email: {e}")


def send_order_to_seller(order, seller_email):
    """Send order notification to seller (product owner)"""
    try:
        items_text = ""
        total = 0
        for item in order.items:
            product_name = item.product.name if item.product else f"Product #{item.product_id}"
            item_total = item.price * item.quantity
            items_text += f"- {product_name} x {item.quantity} = KES {item_total:,.2f}\n"
            total += item_total
        
        msg = Message(
            f"New Order Received - Order #{order.id}",
            recipients=[seller_email]
        )
        msg.body = f"""
Dear Seller,

A new order has been placed for your product!

Order ID: #{order.id}
Customer: {order.user.username} ({order.email})
Phone: {order.phone_number}
Date: {order.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

Items:
{items_text}
Total Amount: KES {total:,.2f}

Delivery Location: {order.location}
Delivery Notes: {order.delivery_notes or 'None'}

Please process this order promptly. You can update the order status from your dashboard.

Thank you for selling with ImoFlames!
"""
        msg.sender = app.config['MAIL_DEFAULT_SENDER']
        mail.send(msg)
        print(f"Order notification sent to seller: {seller_email}")
        
    except Exception as e:
        print(f"Error sending seller email: {e}")


@app.route('/api/orders/<int:order_id>/status', methods=['PUT'])
@token_required
def update_order_status(current_user, order_id):
    """Update order status (admin or product owner)"""
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({'message': 'Order not found'}), 404
        
        # Check permissions: admin OR product owner (for any product in the order)
        has_permission = current_user.is_admin
        if not has_permission:
            for item in order.items:
                if item.product and item.product.user_id == current_user.id:
                    has_permission = True
                    break
        
        if not has_permission:
            return jsonify({'message': 'You do not have permission to update this order'}), 403
        
        data = request.get_json()
        new_status = data.get('status')
        note = data.get('note', '')
        
        valid_statuses = ['pending', 'processing', 'shipped', 'delivered', 'cancelled']
        if new_status not in valid_statuses:
            return jsonify({'message': f'Invalid status. Must be one of: {valid_statuses}'}), 400
        
        old_status = order.status
        
        # Don't update if status is the same
        if old_status == new_status:
            return jsonify({'message': 'Status already set to this value'}), 400
        
        # Update order status
        order.status = new_status
        db.session.commit()
        
        # Create status history entry
        history = OrderStatusHistory(
            order_id=order.id,
            status=new_status,
            note=note,
            created_by=current_user.username
        )
        db.session.add(history)
        db.session.commit()
        
        # Send email notification to customer
        send_order_status_email(order, old_status, new_status, note, order.email)
        
        # Send email to all admins if status is critical
        if new_status in ['cancelled', 'delivered']:
            admins = User.query.filter_by(is_admin=True).all()
            for admin in admins:
                send_order_status_email(order, old_status, new_status, note, admin.email)
        
        return jsonify({
            'message': f'Order status updated to {new_status}',
            'order': order.to_dict(),
            'history': [h.to_dict() for h in order.status_history]
        }), 200
        
    except Exception as e:
        print(f"Error updating order status: {e}")
        db.session.rollback()
        return jsonify({'message': 'Error updating order status'}), 500


@app.route('/api/orders/<int:order_id>/history', methods=['GET'])
@token_required
def get_order_history(current_user, order_id):
    """Get order status history"""
    try:
        order = Order.query.get(order_id)
        if not order:
            return jsonify({'message': 'Order not found'}), 404
        
        # Check if user has permission to view history
        has_permission = (order.user_id == current_user.id) or current_user.is_admin
        if not has_permission:
            for item in order.items:
                if item.product and item.product.user_id == current_user.id:
                    has_permission = True
                    break
        
        if not has_permission:
            return jsonify({'message': 'You do not have permission to view this order'}), 403
        
        history = OrderStatusHistory.query.filter_by(order_id=order.id).order_by(OrderStatusHistory.created_at.desc()).all()
        return jsonify([h.to_dict() for h in history]), 200
        
    except Exception as e:
        print(f"Error fetching order history: {e}")
        return jsonify({'message': 'Error fetching order history'}), 500


@app.route('/api/admin/orders', methods=['GET'])
@token_required
def get_all_orders(current_user):
    """Get all orders for admin"""
    try:
        if not current_user.is_admin:
            return jsonify({'message': 'Admin access required'}), 403
        
        orders = Order.query.order_by(Order.timestamp.desc()).all()
        
        orders_list = []
        for order in orders:
            order_dict = order.to_dict()
            # Add user info
            user = User.query.get(order.user_id)
            if user:
                order_dict['user'] = user.to_dict()
            # Add payment info
            payment = Payment.query.filter_by(order_id=order.id).first()
            if payment:
                order_dict['payment'] = payment.to_dict()
            # Add status history
            history = OrderStatusHistory.query.filter_by(order_id=order.id).order_by(OrderStatusHistory.created_at.desc()).all()
            order_dict['history'] = [h.to_dict() for h in history]
            orders_list.append(order_dict)
        
        return jsonify(orders_list), 200
        
    except Exception as e:
        print(f"Error fetching all orders: {e}")
        return jsonify({'message': 'Error fetching orders'}), 500


@app.route('/api/seller/orders', methods=['GET'])
@token_required
def get_seller_orders(current_user):
    """Get orders for products uploaded by the current user (seller)"""
    try:
        # Get all products uploaded by this user
        user_products = Product.query.filter_by(user_id=current_user.id).all()
        product_ids = [p.id for p in user_products]
        
        if not product_ids:
            return jsonify([]), 200
        
        # Get order items for these products
        order_items = OrderItem.query.filter(OrderItem.product_id.in_(product_ids)).all()
        order_ids = list(set([item.order_id for item in order_items]))
        
        orders = Order.query.filter(Order.id.in_(order_ids)).order_by(Order.timestamp.desc()).all()
        
        orders_list = []
        for order in orders:
            order_dict = order.to_dict()
            # Filter items to only show the seller's products
            filtered_items = []
            for item in order.items:
                if item.product and item.product.user_id == current_user.id:
                    filtered_items.append(item.to_dict())
            order_dict['items'] = filtered_items
            order_dict['total_amount'] = sum([item['price'] * item['quantity'] for item in filtered_items])
            
            # Add user info
            user = User.query.get(order.user_id)
            if user:
                order_dict['user'] = user.to_dict()
            
            # Add payment info
            payment = Payment.query.filter_by(order_id=order.id).first()
            if payment:
                order_dict['payment'] = payment.to_dict()
            
            # Add status history
            history = OrderStatusHistory.query.filter_by(order_id=order.id).order_by(OrderStatusHistory.created_at.desc()).all()
            order_dict['history'] = [h.to_dict() for h in history]
            
            orders_list.append(order_dict)
        
        return jsonify(orders_list), 200
        
    except Exception as e:
        print(f"Error fetching seller orders: {e}")
        return jsonify({'message': 'Error fetching orders'}), 500


@app.route('/api/orders/<int:order_id>', methods=['DELETE'])
@token_required
def delete_order(current_user, order_id):
    """Delete an order (admin only) - Manual cleanup version"""
    try:
        # Check if user is admin
        if not current_user.is_admin:
            return jsonify({'message': 'Admin access required'}), 403
        
        # Find the order
        order = Order.query.get(order_id)
        if not order:
            return jsonify({'message': 'Order not found'}), 404
        
        # Don't allow deletion of delivered orders
        if order.status == 'delivered':
            return jsonify({'message': 'Cannot delete delivered orders'}), 400
        
        # Store email before deletion
        customer_email = order.email
        order_id_copy = order.id
        
        # Manually delete related records in correct order
        # 1. Delete order status history
        OrderStatusHistory.query.filter_by(order_id=order.id).delete()
        
        # 2. Delete order items
        OrderItem.query.filter_by(order_id=order.id).delete()
        
        # 3. Update payments to remove order reference (set NULL instead of deleting)
        Payment.query.filter_by(order_id=order.id).update({'order_id': None})
        
        # 4. Finally delete the order
        db.session.delete(order)
        db.session.commit()
        
        # Send notification email
        try:
            msg = Message(
                f"Order #{order_id_copy} Cancelled",
                recipients=[customer_email]
            )
            msg.body = f"""
Dear Customer,

Your order #{order_id_copy} has been cancelled by the administrator.

If you have any questions, please contact support.

Thank you,
ImoFlames Team
"""
            msg.sender = app.config['MAIL_DEFAULT_SENDER']
            mail.send(msg)
        except Exception as email_error:
            print(f"Failed to send cancellation email: {email_error}")
        
        return jsonify({'message': 'Order deleted successfully'}), 200
        
    except Exception as e:
        print(f"Error deleting order: {e}")
        db.session.rollback()
        return jsonify({'message': f'Error deleting order: {str(e)}'}), 500

# Add these proper endpoints to your app.py

@app.route('/api/products/featured', methods=['GET'])
def get_featured_products():
    """Get featured products - products with highest ratings or random approved"""
    try:
        # Try to get products with reviews first
        featured = db.session.query(Product).outerjoin(Review).group_by(Product.id).order_by(db.func.count(Review.id).desc()).limit(8).all()
        
        if not featured or len(featured) < 4:
            # Fallback to recent products
            featured = Product.query.filter_by(is_approved=True).order_by(Product.id.desc()).limit(8).all()
        
        if not featured:
            featured = Product.query.filter_by(is_approved=True).limit(8).all()
        
        return jsonify([product.to_dict() for product in featured]), 200
    except Exception as e:
        print(f"Error fetching featured products: {e}")
        return jsonify([]), 200


@app.route('/api/products/trending', methods=['GET'])
def get_trending_products():
    """Get trending products - most ordered products in last 30 days"""
    try:
        from datetime import datetime, timedelta
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        
        # Get products ordered in last 30 days
        trending = db.session.query(
            Product,
            db.func.count(OrderItem.product_id).label('order_count')
        ).join(OrderItem, Product.id == OrderItem.product_id)\
         .join(Order, Order.id == OrderItem.order_id)\
         .filter(Order.timestamp >= thirty_days_ago)\
         .filter(Product.is_approved == True)\
         .group_by(Product.id)\
         .order_by(db.text('order_count DESC'))\
         .limit(8).all()
        
        # If no trending products, get most ordered overall
        if not trending:
            trending = db.session.query(
                Product,
                db.func.count(OrderItem.product_id).label('order_count')
            ).join(OrderItem, Product.id == OrderItem.product_id)\
             .filter(Product.is_approved == True)\
             .group_by(Product.id)\
             .order_by(db.text('order_count DESC'))\
             .limit(8).all()
        
        # If still no trending, return featured as fallback
        if not trending:
            featured = Product.query.filter_by(is_approved=True).order_by(Product.id.desc()).limit(8).all()
            return jsonify([product.to_dict() for product in featured]), 200
        
        return jsonify([product.to_dict() for product, count in trending]), 200
    except Exception as e:
        print(f"Error fetching trending products: {e}")
        # Fallback to recent products
        try:
            fallback = Product.query.filter_by(is_approved=True).order_by(Product.id.desc()).limit(8).all()
            return jsonify([product.to_dict() for product in fallback]), 200
        except:
            return jsonify([]), 200


@app.route('/api/products/popular', methods=['GET'])
def get_popular_products():
    """Get most popular products - most added to cart"""
    try:
        # Get products most frequently added to cart
        popular = db.session.query(
            Product,
            db.func.sum(Cart.quantity).label('total_quantity')
        ).join(Cart, Product.id == Cart.product_id)\
         .filter(Product.is_approved == True)\
         .group_by(Product.id)\
         .order_by(db.text('total_quantity DESC'))\
         .limit(8).all()
        
        # If no popular products, get products with most orders
        if not popular:
            popular = db.session.query(
                Product,
                db.func.count(OrderItem.product_id).label('order_count')
            ).join(OrderItem, Product.id == OrderItem.product_id)\
             .filter(Product.is_approved == True)\
             .group_by(Product.id)\
             .order_by(db.text('order_count DESC'))\
             .limit(8).all()
        
        # If still no popular, return recent products
        if not popular:
            recent = Product.query.filter_by(is_approved=True).order_by(Product.id.desc()).limit(8).all()
            return jsonify([product.to_dict() for product in recent]), 200
        
        return jsonify([product.to_dict() for product, count in popular]), 200
    except Exception as e:
        print(f"Error fetching popular products: {e}")
        try:
            fallback = Product.query.filter_by(is_approved=True).order_by(Product.id.desc()).limit(8).all()
            return jsonify([product.to_dict() for product in fallback]), 200
        except:
            return jsonify([]), 200


@app.route('/api/products/recommended', methods=['GET'])
@token_required
def get_recommended_products(current_user):
    """Get personalized recommendations based on user's browsing/purchase history"""
    try:
        # Get user's purchased products
        purchased_items = db.session.query(OrderItem.product_id).join(Order).filter(Order.user_id == current_user.id).all()
        purchased_ids = [item[0] for item in purchased_items]
        
        # Get user's cart items
        cart_items = Cart.query.filter_by(user_id=current_user.id).all()
        cart_ids = [item.product_id for item in cart_items]
        
        # Combine viewed/purchased/cart items
        user_products = list(set(purchased_ids + cart_ids))
        
        if user_products:
            # Get categories from user's products
            user_products_data = Product.query.filter(Product.id.in_(user_products)).all()
            categories = list(set([p.category for p in user_products_data if p.category]))
            
            if categories:
                # Recommend products from same categories, excluding already seen
                recommended = Product.query.filter(
                    Product.category.in_(categories),
                    Product.is_approved == True,
                    ~Product.id.in_(user_products)
                ).order_by(db.func.random()).limit(8).all()
                
                if len(recommended) >= 4:
                    return jsonify([product.to_dict() for product in recommended]), 200
        
        # If not enough recommendations, get trending products
        trending = Product.query.filter_by(is_approved=True).order_by(Product.id.desc()).limit(8).all()
        return jsonify([product.to_dict() for product in trending]), 200
        
    except Exception as e:
        print(f"Error fetching recommendations: {e}")
        try:
            fallback = Product.query.filter_by(is_approved=True).order_by(Product.id.desc()).limit(8).all()
            return jsonify([product.to_dict() for product in fallback]), 200
        except:
            return jsonify([]), 200       
if __name__ == '__main__':
    app.run(debug=True)