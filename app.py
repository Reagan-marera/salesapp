from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_mail import Mail, Message
from models import db, User, Product, Order,OTP
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

# JWT Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
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
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400

    is_admin_request = data.get('is_admin', False)
    requesting_user = None

    if 'Authorization' in request.headers:
        token = request.headers['Authorization'].split(" ")[1]
        try:
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            requesting_user = User.query.get(decoded['user_id'])
        except:
            pass

    new_user = User(
        username=data['username'],
        email=data['email'],
        is_admin=is_admin_request
    )
    new_user.set_password(data['password'])

    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password'}), 400

    user = User.query.filter_by(username=data['username']).first()

    if not user or not user.check_password(data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401

    token = jwt.encode({
        'user_id': user.id,
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, app.config['SECRET_KEY'])

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

@app.route('/api/cart/add/<int:product_id>', methods=['POST'])
@token_required
def add_to_cart(current_user, product_id):
    # Check if product exists
    product = Product.query.get_or_404(product_id)
    
    # Prevent adding same product multiple times
    existing_order = Order.query.filter_by(
        user_id=current_user.id,
        product_id=product_id,
        status='pending'
    ).first()
    
    if existing_order:
        return jsonify({'message': 'Product already in cart'}), 400
    
    new_order = Order(
        product_id=product_id,
        user_id=current_user.id,
        phone_number="",
        email="",
        location="",
        status='pending',
        timestamp=datetime.utcnow()
    )
    
    db.session.add(new_order)
    db.session.commit()
    
    return jsonify({'message': 'Added to cart', 'order_id': new_order.id}), 201

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

@app.route('/api/users', methods=['GET', 'OPTIONS'])
@cross_origin()
@token_required
@admin_required
def get_users(current_user):
    print(request.headers)
    if request.method == 'OPTIONS':
        response = jsonify({})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
        response.headers.add('Access-Control-Allow-Methods', 'GET,OPTIONS')
        return response, 200

    users = User.query.all()
    return jsonify([user.to_dict() for user in users]), 200

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

if __name__ == '__main__':
    app.run(debug=True)