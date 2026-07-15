from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_mail import Mail, Message
from models import db, User, Product, OTP, Review, Favorite, ContactInquiry
from werkzeug.utils import secure_filename
import os
import uuid
import random
import string
import jwt
import datetime
from datetime import datetime, timedelta
import base64
from functools import wraps
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash

# Initialize Flask App
app = Flask(__name__)
application = app

CORS(app)

app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///carmarket.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'mail.classicmotors.co.ke'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USERNAME'] = 'admin@classicmotors.co.ke'
app.config['MAIL_PASSWORD'] = 'your-email-password'
app.config['MAIL_DEFAULT_SENDER'] = 'admin@classicmotors.co.ke'
# At the top of app.py, make sure this is set:
ADMIN_SECRET = 'classicvendor#2024#'  # This is the vendor code for sellers
ADMIN_REGISTRATION_CODE = 'classicmoters#2024#'  # This is the admin registration code
mail = Mail(app)

# Initialize DB
db.init_app(app)
migrate = Migrate(app, db)

# Create tables
with app.app_context():
    db.create_all()

# Allowed file types
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
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

# ==================== AUTH ENDPOINTS ====================

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()

    if not data or not data.get('username') or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing required fields'}), 400

    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'Username already exists'}), 400

    if User.query.filter_by(email=data['email']).first():
        return jsonify({'message': 'Email already registered'}), 400

    # Get registration type
    register_type = data.get('register_type', 'user')
    
    # ADMIN SECRET - Use the same secret you're using in the frontend
    ADMIN_SECRET = 'classicmoters#2024#'  # Your actual admin secret
    
    # Get phone number and clean it
    phone_number = data.get('phone_number', '').strip()
    # If phone number is empty or same as username, set to None
    if not phone_number or phone_number == data.get('username'):
        phone_number = None
    
    # Check if this is an admin registration
    is_admin = False
    admin_code = data.get('admin_code')
    
    if register_type == 'admin':
        # Verify admin code - using the actual secret
        if admin_code == ADMIN_SECRET:
            is_admin = True
        else:
            return jsonify({'message': 'Invalid admin registration code'}), 403

    # Check if this is a seller registration
    is_seller = False
    admin_secret = data.get('admin_secret')
    seller_info = data.get('seller_info', {})
    
    if register_type == 'seller':
        if admin_secret and admin_secret == ADMIN_SECRET:
            is_seller = True
        else:
            return jsonify({'message': 'Invalid vendor authorization code'}), 403

    # Create user based on type
    if is_admin:
        new_user = User(
            username=data['username'],
            email=data['email'],
            phone_number=phone_number,  # Use cleaned phone number
            is_admin=True,
            can_upload=True,
            role='admin',
            status='active'
        )
    elif is_seller:
        new_user = User(
            username=data['username'],
            email=data['email'],
            phone_number=phone_number,  # Use cleaned phone number
            is_admin=False,
            can_upload=False,
            role='seller_pending',
            status='pending',
            seller_info=seller_info
        )
    else:
        # Regular user
        new_user = User(
            username=data['username'],
            email=data['email'],
            phone_number=phone_number,  # Use cleaned phone number
            is_admin=False,
            can_upload=False,
            role='user',
            status='active'
        )
    
    new_user.set_password(data['password'])
    db.session.add(new_user)
    db.session.commit()

    # Send notifications for seller registration
    if is_seller:
        admins = User.query.filter_by(is_admin=True).all()
        for admin in admins:
            try:
                msg = Message(
                    f"New Seller Registration - {new_user.username}",
                    recipients=[admin.email]
                )
                msg.body = f"""
New Seller Registration Alert!

Username: {new_user.username}
Email: {new_user.email}
Phone: {new_user.phone_number if new_user.phone_number else 'Not provided'}
Business: {seller_info.get('business_name', 'N/A')}
Seller Name: {seller_info.get('seller_name', 'N/A')}
ID Number: {seller_info.get('id_number', 'N/A')}

Please review and approve this seller account.
"""
                msg.sender = app.config['MAIL_DEFAULT_SENDER']
                mail.send(msg)
            except Exception as e:
                print(f"Failed to send admin notification: {e}")

    return jsonify({
        'message': 'User created successfully', 
        'requires_approval': is_seller,
        'is_admin': is_admin,
        'user': new_user.to_dict()
    }), 201
@app.route('/api/user/update-phone', methods=['PUT'])
@token_required
def update_phone_number(current_user):
    """Update user's phone number"""
    data = request.get_json()
    phone_number = data.get('phone_number', '').strip()
    
    if not phone_number:
        return jsonify({'message': 'Phone number is required'}), 400
    
    # Validate phone number format (Kenyan format)
    if not phone_number.startswith('0') and not phone_number.startswith('254'):
        return jsonify({'message': 'Please enter a valid Kenyan phone number'}), 400
    
    # Update phone number
    current_user.phone_number = phone_number
    db.session.commit()
    
    return jsonify({
        'message': 'Phone number updated successfully',
        'phone_number': current_user.phone_number,
        'user': current_user.to_dict()
    }), 200
# ==================== ADMIN ENDPOINTS ====================
@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@token_required
@admin_required
def admin_update_user(current_user, user_id):
    """Admin endpoint to update user details"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        data = request.get_json()
        
        # Update fields
        if 'username' in data and data['username']:
            # Check if username is taken by another user
            existing = User.query.filter(
                User.username == data['username'],
                User.id != user_id
            ).first()
            if existing:
                return jsonify({'message': 'Username already taken'}), 400
            user.username = data['username']
        
        if 'email' in data and data['email']:
            existing = User.query.filter(
                User.email == data['email'],
                User.id != user_id
            ).first()
            if existing:
                return jsonify({'message': 'Email already registered'}), 400
            user.email = data['email']
        
        if 'phone_number' in data:
            phone = data['phone_number'].strip()
            # Don't allow username to be stored as phone number
            if phone and phone != user.username:
                user.phone_number = phone
            else:
                user.phone_number = None
        
        db.session.commit()
        
        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error updating user: {e}")
        return jsonify({'message': 'Failed to update user'}), 500
@app.route('/api/admin/products', methods=['GET'])
@token_required

def admin_get_products(current_user):
    """Get all products for admin (including unapproved)"""
    try:
        # Get all products, ordered by created_at descending
        products = Product.query.order_by(Product.created_at.desc()).all()
        return jsonify([product.to_dict() for product in products]), 200
    except Exception as e:
        print(f"Error fetching admin products: {e}")
        return jsonify([]), 200

@app.route('/api/admin/users', methods=['GET'])
@token_required
@admin_required
def admin_get_users(current_user):
    """Get all users for admin"""
    try:
        users = User.query.order_by(User.created_at.desc()).all()
        return jsonify([user.to_dict() for user in users]), 200
    except Exception as e:
        print(f"Error fetching users: {e}")
        return jsonify([]), 200

@app.route('/api/admin/sellers', methods=['GET'])
@token_required
@admin_required
def admin_get_pending_sellers(current_user):
    """Get all pending seller registrations"""
    try:
        pending_sellers = User.query.filter_by(role='seller_pending').all()
        return jsonify([user.to_dict() for user in pending_sellers]), 200
    except Exception as e:
        print(f"Error fetching pending sellers: {e}")
        return jsonify([]), 200

@app.route('/api/admin/sellers/<int:user_id>/approve', methods=['PUT'])
@token_required
@admin_required
def admin_approve_seller(current_user, user_id):
    """Approve a seller registration"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        if user.role != 'seller_pending':
            return jsonify({'message': 'User is not a pending seller'}), 400
        
        user.role = 'seller_approved'
        user.can_upload = True
        user.status = 'active'
        
        # Update seller_info with approval
        if user.seller_info:
            user.seller_info['approval_status'] = 'approved'
            user.seller_info['approved_at'] = datetime.utcnow().isoformat()
            user.seller_info['approved_by'] = current_user.username
        
        db.session.commit()
        
        # Send approval email
        try:
            msg = Message(
                "Seller Account Approved - ClassicMoters",
                recipients=[user.email]
            )
            msg.body = f"""
Dear {user.username},

Congratulations! Your seller account has been approved.

You can now upload cars for sale on ClassicMoters.

Business: {user.seller_info.get('business_name', 'N/A') if user.seller_info else 'N/A'}

Log in to your account to start listing your cars.

Thank you for choosing ClassicMoters!
"""
            msg.sender = app.config['MAIL_DEFAULT_SENDER']
            mail.send(msg)
        except Exception as e:
            print(f"Failed to send approval email: {e}")
        
        return jsonify({'message': 'Seller approved successfully', 'user': user.to_dict()}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error approving seller: {e}")
        return jsonify({'message': 'Failed to approve seller'}), 500

@app.route('/api/admin/sellers/<int:user_id>/reject', methods=['PUT'])
@token_required
@admin_required
def admin_reject_seller(current_user, user_id):
    """Reject a seller registration"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        if user.role != 'seller_pending':
            return jsonify({'message': 'User is not a pending seller'}), 400
        
        user.role = 'user'
        user.status = 'rejected'
        
        # Update seller_info with rejection
        if user.seller_info:
            user.seller_info['approval_status'] = 'rejected'
            user.seller_info['rejected_at'] = datetime.utcnow().isoformat()
            user.seller_info['rejected_by'] = current_user.username
        
        db.session.commit()
        
        # Send rejection email
        try:
            msg = Message(
                "Seller Application Status - ClassicMoters",
                recipients=[user.email]
            )
            msg.body = f"""
Dear {user.username},

Thank you for your interest in becoming a seller on ClassicMoters.

After review, we regret to inform you that your seller application has been rejected.

Reason: Our team has determined that your application does not meet our current requirements.

You can reapply after 30 days with additional information.

Thank you for your understanding.
"""
            msg.sender = app.config['MAIL_DEFAULT_SENDER']
            mail.send(msg)
        except Exception as e:
            print(f"Failed to send rejection email: {e}")
        
        return jsonify({'message': 'Seller rejected successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error rejecting seller: {e}")
        return jsonify({'message': 'Failed to reject seller'}), 500

@app.route('/api/admin/stats', methods=['GET'])
@token_required
@admin_required
def admin_get_stats(current_user):
    """Get admin dashboard statistics"""
    try:
        total_users = User.query.count()
        total_products = Product.query.count()
        pending_products = Product.query.filter_by(is_approved=False).count()
        pending_sellers = User.query.filter_by(role='seller_pending').count()
        total_reviews = Review.query.count()
        
        return jsonify({
            'total_users': total_users,
            'total_products': total_products,
            'pending_products': pending_products,
            'pending_sellers': pending_sellers,
            'total_reviews': total_reviews
        }), 200
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return jsonify({
            'total_users': 0,
            'total_products': 0,
            'pending_products': 0,
            'pending_sellers': 0,
            'total_reviews': 0
        }), 200

# ==================== SEARCH ENDPOINT ====================

@app.route('/api/search', methods=['GET'])
def search_products():
    """Search products with filters"""
    try:
        query = request.args.get('q', '')
        category = request.args.get('category', '')
        min_price = request.args.get('minPrice')
        max_price = request.args.get('maxPrice')
        sort_by = request.args.get('sort', 'relevance')
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 12))

        # Build filters
        filters = [Product.is_approved == True]
        
        if query:
            search_term = f"%{query.replace(' ', '%')}%"
            filters.append(
                db.or_(
                    Product.name.ilike(search_term),
                    Product.brand.ilike(search_term),
                    Product.category.ilike(search_term),
                    Product.location.ilike(search_term),
                    Product.seller_name.ilike(search_term)
                )
            )
        
        if category and category != 'All':
            filters.append(Product.category == category)
        
        if min_price:
            try:
                filters.append(Product.price >= float(min_price))
            except ValueError:
                pass
        
        if max_price:
            try:
                filters.append(Product.price <= float(max_price))
            except ValueError:
                pass

        # Build query
        query_obj = Product.query.filter(*filters)
        
        # Apply sorting
        if sort_by == 'price-low':
            query_obj = query_obj.order_by(Product.price.asc())
        elif sort_by == 'price-high':
            query_obj = query_obj.order_by(Product.price.desc())
        elif sort_by == 'newest':
            query_obj = query_obj.order_by(Product.created_at.desc())
        elif sort_by == 'oldest':
            query_obj = query_obj.order_by(Product.created_at.asc())
        elif sort_by == 'rating':
            # Subquery for average rating
            from sqlalchemy import func
            query_obj = query_obj.outerjoin(Review).group_by(Product.id).order_by(func.avg(Review.rating).desc())

        # Paginate
        paginated = query_obj.paginate(page=page, per_page=limit, error_out=False)
        
        # Get results with ratings
        results = []
        for product in paginated.items:
            product_dict = product.to_dict()
            # Add rating info
            reviews = Review.query.filter_by(product_id=product.id).all()
            if reviews:
                avg_rating = sum(r.rating for r in reviews) / len(reviews)
                product_dict['rating'] = round(avg_rating, 1)
                product_dict['review_count'] = len(reviews)
            else:
                product_dict['rating'] = 0
                product_dict['review_count'] = 0
            results.append(product_dict)
        
        return jsonify({
            'results': results,
            'total': paginated.total,
            'totalPages': paginated.pages,
            'currentPage': page,
            'perPage': limit
        }), 200
        
    except Exception as e:
        print(f"Search error: {e}")
        return jsonify({
            'results': [],
            'total': 0,
            'totalPages': 0,
            'currentPage': 1,
            'perPage': 12
        }), 200
@app.route('/api/auth/google', methods=['POST'])
def google_auth():
    if request.method == 'OPTIONS':
        return jsonify({}), 200
    
    try:
        data = request.get_json()
        google_id = data.get('googleId')
        email = data.get('email')
        username = data.get('username')
        picture = data.get('picture')
        
        if not google_id or not email:
            return jsonify({'message': 'Missing required fields'}), 400
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Check if username exists
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
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
                is_verified=True,
                can_upload=False,
                is_admin=False,
                role='user',
                status='active'
            )
            db.session.add(user)
            db.session.commit()
        else:
            if not user.google_id:
                user.google_id = google_id
            if picture and not user.profile_picture:
                user.profile_picture = picture
            db.session.commit()
        
        token = jwt.encode({
            'user_id': user.id,
            'email': user.email,
            'username': user.username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        
        return jsonify({'token': token, 'user': user.to_dict()}), 200
        
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
    user = User.query.filter(
        (User.username == identifier) | (User.email == identifier)
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

@app.route('/api/users/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    return jsonify(current_user.to_dict()), 200

@app.route('/api/user/profile', methods=['GET', 'PUT'])
@token_required
def user_profile(current_user):
    if request.method == 'GET':
        return jsonify(current_user.to_dict()), 200
    
    elif request.method == 'PUT':
        data = request.get_json()
        current_user.username = data.get('username', current_user.username)
        current_user.email = data.get('email', current_user.email)
        current_user.phone_number = data.get('phone_number', current_user.phone_number)
        current_user.profile_picture = data.get('profile_picture', current_user.profile_picture)
        db.session.commit()
        return jsonify(current_user.to_dict()), 200

@app.route('/api/user/change-password', methods=['PUT'])
@token_required
def change_password(current_user):
    data = request.get_json()
    if not current_user.check_password(data.get('current_password')):
        return jsonify({'message': 'Current password is incorrect'}), 401
    
    current_user.set_password(data.get('new_password'))
    db.session.commit()
    return jsonify({'message': 'Password changed successfully'}), 200

# ==================== PASSWORD RESET ENDPOINTS ====================

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

@app.route('/api/request_reset_password', methods=['POST'])
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

    try:
        msg = Message('Password Reset Request', recipients=[email])
        msg.body = f"""
Hello {user.username},

Here's your verification code to reset your password:

{otp}

This code will expire in 5 minutes.

If you did not request this, please ignore this email.
"""
        msg.sender = app.config['MAIL_DEFAULT_SENDER']
        mail.send(msg)
        return jsonify({"message": "OTP sent to your email"}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500

@app.route('/api/reset_password', methods=['POST'])
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
        return jsonify({"error": "User not found"}), 404

    user.set_password(new_password)
    db.session.commit()
    db.session.delete(otp_entry)
    db.session.commit()

    return jsonify({"message": "Password reset successfully"}), 200

# ==================== PRODUCT ENDPOINTS ====================

@app.route('/api/products', methods=['GET'])
def get_products():
    search = request.args.get('search', '').strip().lower() if request.args.get('search') else None
    min_price = request.args.get('min')
    max_price = request.args.get('max')
    category = request.args.get('category', '').strip().lower() if request.args.get('category') else None
    page = int(request.args.get('page', 1))
    limit = int(request.args.get('limit', 20))

    filters = [Product.is_approved == True]
    
    if search:
        search_term = f"%{search.replace(' ', '%')}%"
        filters.append(Product.name.ilike(search_term))
    if min_price:
        try:
            filters.append(Product.price >= float(min_price))
        except ValueError:
            pass
    if max_price:
        try:
            filters.append(Product.price <= float(max_price))
        except ValueError:
            pass
    if category:
        filters.append(Product.category.ilike(f"%{category}%"))

    paginated_products = Product.query.filter(*filters).paginate(page=page, per_page=limit, error_out=False)
    products = paginated_products.items
    total_pages = paginated_products.pages
    total_products = paginated_products.total

    return jsonify({
        'products': [product.to_dict() for product in products],
        'totalPages': total_pages,
        'totalProducts': total_products,
    })

@app.route('/api/products/<int:product_id>', methods=['GET'])
def get_product(product_id):
    try:
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'message': 'Product not found'}), 404
        
        # Increment view count
        product.views = (product.views or 0) + 1
        db.session.commit()
        
        return jsonify(product.to_dict()), 200
    except Exception as e:
        print(f"Error fetching product: {e}")
        return jsonify({'message': 'Error fetching product'}), 500

@app.route('/api/products/featured', methods=['GET'])
def get_featured_products():
    try:
        featured = Product.query.filter_by(is_approved=True, is_featured=True).order_by(Product.id.desc()).limit(8).all()
        if not featured or len(featured) < 4:
            featured = Product.query.filter_by(is_approved=True).order_by(Product.id.desc()).limit(8).all()
        if not featured:
            featured = Product.query.filter_by(is_approved=True).limit(8).all()
        return jsonify([product.to_dict() for product in featured]), 200
    except Exception as e:
        print(f"Error fetching featured products: {e}")
        return jsonify([]), 200


@app.route('/api/products', methods=['POST'])
@token_required
def create_product(current_user):
    if not current_user.is_admin and not current_user.can_upload:
        return jsonify({
            'message': 'You do not have permission to upload products',
            'reason': 'admin_approval_required'
        }), 403

    # Check if files were sent
    if 'images' not in request.files:
        return jsonify({'message': 'No image file provided. Please upload at least one image.'}), 400

    files = request.files.getlist('images')
    # Filter out empty files
    files = [f for f in files if f and f.filename]
    
    if len(files) == 0:
        return jsonify({'message': 'No valid image files selected. Please select at least one image.'}), 400

    data = request.form
    if not data.get('name'):
        return jsonify({'message': 'Product name is required'}), 400

    if not data.get('price') or not data.get('price').replace('.', '', 1).isdigit():
        return jsonify({'message': 'Valid price is required'}), 400

    # Check main file
    main_file = files[0]
    if not main_file or not main_file.filename:
        return jsonify({'message': 'Invalid main image file'}), 400

    # Allow all common image types
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp', 'svg', 'ico', 'tiff', 'tif'}
    
    def allowed_file(filename):
        return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

    if not allowed_file(main_file.filename):
        return jsonify({
            'message': f'Invalid image file type. Allowed types: {", ".join(ALLOWED_EXTENSIONS)}'
        }), 400

    try:
        # Create upload directory if it doesn't exist
        upload_folder = app.config['UPLOAD_FOLDER']
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        # Save main image
        filename = secure_filename(main_file.filename)
        # Generate unique filename to prevent collisions
        name, ext = os.path.splitext(filename)
        unique_filename = f"{uuid.uuid4().hex}_{name}{ext}"
        main_file.save(os.path.join(upload_folder, unique_filename))

        # Save extra images
        extra_image_paths = []
        for file in files[1:]:
            if file and file.filename and allowed_file(file.filename):
                ext_filename = secure_filename(file.filename)
                name, ext = os.path.splitext(ext_filename)
                ext_unique = f"{uuid.uuid4().hex}_{name}{ext}"
                file.save(os.path.join(upload_folder, ext_unique))
                extra_image_paths.append(ext_unique)

        new_product = Product(
            name=data['name'],
            description=data.get('description', ''),
            price=float(data['price']),
            image_path=unique_filename,
            extra_images=",".join(extra_image_paths),
            category=data.get('category', ''),
            brand=data.get('brand', ''),
            year=int(data.get('year', 0)) if data.get('year') else None,
            mileage=data.get('mileage', ''),
            fuel=data.get('fuel', ''),
            transmission=data.get('transmission', ''),
            location=data.get('location', ''),
            color=data.get('color', ''),
            condition=data.get('condition', 'Used'),
            seller_name=data.get('seller', current_user.username),
            seller_phone=data.get('phone', current_user.phone_number),
            is_approved=current_user.is_admin,
            user_id=current_user.id,
            status='active' if current_user.is_admin else 'pending'
        )

        db.session.add(new_product)
        db.session.commit()

        # Notify admin if product needs approval
        if not current_user.is_admin:
            admins = User.query.filter_by(is_admin=True).all()
            for admin in admins:
                try:
                    msg = Message(
                        f"New Product Needs Approval - {new_product.name}",
                        recipients=[admin.email]
                    )
                    msg.body = f"""
New product uploaded by {current_user.username} needs approval.

Product: {new_product.name}
Price: KES {new_product.price}
Category: {new_product.category}
Brand: {new_product.brand}

Please review and approve this product.
"""
                    msg.sender = app.config['MAIL_DEFAULT_SENDER']
                    mail.send(msg)
                except Exception as e:
                    print(f"Failed to send approval email: {e}")

        return jsonify(new_product.to_dict()), 201

    except Exception as e:
        db.session.rollback()
        print("Upload error:", str(e))
        import traceback
        traceback.print_exc()
        return jsonify({'message': f'Failed to upload product: {str(e)}'}), 500
@app.route('/api/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(current_user, product_id):
    product = Product.query.get(product_id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    
    if product.user_id != current_user.id and not current_user.is_admin:
        return jsonify({'message': 'You do not have permission to update this product'}), 403
    
    data = request.form
    
    if not data.get('name'):
        return jsonify({'message': 'Product name is required'}), 400
    
    if not data.get('price') or not data.get('price').replace('.', '', 1).isdigit():
        return jsonify({'message': 'Valid price is required'}), 400
    
    try:
        # Handle images if provided
        if 'images' in request.files:
            files = request.files.getlist('images')
            if files and files[0]:
                main_file = files[0]
                if not allowed_file(main_file.filename):
                    return jsonify({'message': 'Invalid image file type'}), 400
                
                if product.image_path:
                    try:
                        os.remove(os.path.join(app.config['UPLOAD_FOLDER'], product.image_path))
                    except OSError:
                        pass
                
                filename = secure_filename(main_file.filename)
                unique_filename = f"{uuid.uuid4().hex}_{filename}"
                main_file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_filename))
                product.image_path = unique_filename
        
        # Update fields
        product.name = data['name']
        product.description = data.get('description', product.description)
        product.price = float(data['price'])
        product.category = data.get('category', product.category)
        product.brand = data.get('brand', product.brand)
        product.year = int(data.get('year', 0)) if data.get('year') else None
        product.mileage = data.get('mileage', product.mileage)
        product.fuel = data.get('fuel', product.fuel)
        product.transmission = data.get('transmission', product.transmission)
        product.location = data.get('location', product.location)
        product.color = data.get('color', product.color)
        product.condition = data.get('condition', product.condition)
        product.seller_name = data.get('seller', product.seller_name)
        product.seller_phone = data.get('phone', product.seller_phone)
        
        if not current_user.is_admin:
            product.is_approved = False
            product.status = 'pending'
        
        db.session.commit()
        return jsonify(product.to_dict()), 200
    
    except Exception as e:
        db.session.rollback()
        print("Update error:", str(e))
        return jsonify({'message': 'Failed to update product'}), 500

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    product = Product.query.get_or_404(product_id)

    if not (product.user_id == current_user.id or current_user.is_admin):
        return jsonify({'message': 'Unauthorized: You can only delete your own products'}), 403

    try:
        all_images = [product.image_path]
        if product.extra_images:
            all_images.extend(product.extra_images.split(','))
        
        for image in all_images:
            if image:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], image)
                if os.path.exists(file_path):
                    os.remove(file_path)
        
        db.session.delete(product)
        db.session.commit()
        return jsonify({'message': 'Product deleted successfully'}), 200

    except Exception as e:
        db.session.rollback()
        print(f'Error deleting product: {str(e)}')
        return jsonify({'message': 'Failed to delete product'}), 500

@app.route('/api/products/<int:product_id>/approve', methods=['PUT'])
@token_required
@admin_required
def approve_product(current_user, product_id):
    product = Product.query.get_or_404(product_id)
    product.is_approved = True
    product.status = 'active'
    product.approved_at = datetime.utcnow()
    product.approved_by = current_user.id
    db.session.commit()
    return jsonify(product.to_dict()), 200

# ==================== REVIEW ENDPOINTS ====================

@app.route('/api/products/<int:product_id>/reviews', methods=['GET'])
def get_product_reviews(product_id):
    reviews = Review.query.filter_by(product_id=product_id).order_by(Review.created_at.desc()).all()
    return jsonify([review.to_dict() for review in reviews]), 200

@app.route('/api/products/<int:product_id>/reviews', methods=['POST'])
@token_required
def create_review(current_user, product_id):
    data = request.get_json()
    rating = data.get('rating')
    comment = data.get('comment')
    
    if not rating or rating < 1 or rating > 5:
        return jsonify({'message': 'Rating must be between 1 and 5'}), 400
    
    existing_review = Review.query.filter_by(product_id=product_id, user_id=current_user.id).first()
    if existing_review:
        existing_review.rating = rating
        existing_review.comment = comment
        db.session.commit()
        return jsonify(existing_review.to_dict()), 200
    
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

@app.route('/api/products/<int:product_id>/reviews', methods=['PUT'])
@token_required
def update_review(current_user, product_id):
    data = request.get_json()
    review = Review.query.filter_by(product_id=product_id, user_id=current_user.id).first()
    if not review:
        return jsonify({'message': 'Review not found'}), 404
    
    if data.get('rating'):
        review.rating = data['rating']
    if 'comment' in data:
        review.comment = data['comment']
    
    db.session.commit()
    return jsonify(review.to_dict()), 200

@app.route('/api/products/<int:product_id>/reviews', methods=['DELETE'])
@token_required
def delete_review(current_user, product_id):
    review = Review.query.filter_by(product_id=product_id, user_id=current_user.id).first()
    if not review:
        return jsonify({'message': 'Review not found'}), 404
    
    db.session.delete(review)
    db.session.commit()
    return jsonify({'message': 'Review deleted successfully'}), 200

# ==================== FAVORITES ENDPOINTS ====================

@app.route('/api/favorites', methods=['GET'])
@token_required
def get_favorites(current_user):
    try:
        favorites = Favorite.query.filter_by(user_id=current_user.id).all()
        product_ids = [f.product_id for f in favorites]
        products = Product.query.filter(Product.id.in_(product_ids)).all() if product_ids else []
        return jsonify([product.to_dict() for product in products]), 200
    except Exception as e:
        print(f"Error fetching favorites: {e}")
        return jsonify([]), 200

@app.route('/api/favorites/<int:product_id>', methods=['POST'])
@token_required
def add_favorite(current_user, product_id):
    try:
        existing = Favorite.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if existing:
            return jsonify({'message': 'Already in favorites'}), 400
        
        favorite = Favorite(user_id=current_user.id, product_id=product_id)
        db.session.add(favorite)
        db.session.commit()
        return jsonify({'message': 'Added to favorites'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to add favorite'}), 500

@app.route('/api/favorites/<int:product_id>', methods=['DELETE'])
@token_required
def remove_favorite(current_user, product_id):
    try:
        favorite = Favorite.query.filter_by(user_id=current_user.id, product_id=product_id).first()
        if not favorite:
            return jsonify({'message': 'Favorite not found'}), 404
        
        db.session.delete(favorite)
        db.session.commit()
        return jsonify({'message': 'Removed from favorites'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'message': 'Failed to remove favorite'}), 500

# ==================== USER PRODUCTS ENDPOINTS ====================

@app.route('/api/user/products', methods=['GET'])
@token_required
def get_user_products(current_user):
    """Get all products uploaded by the current user"""
    try:
        products = Product.query.filter_by(user_id=current_user.id).order_by(Product.created_at.desc()).all()
        return jsonify([product.to_dict() for product in products]), 200
    except Exception as e:
        print(f"Error fetching user products: {e}")
        return jsonify([]), 200

# ==================== SELLER MANAGEMENT ENDPOINTS ====================

@app.route('/api/admin/sellers', methods=['GET'])
@token_required
@admin_required
def get_pending_sellers(current_user):
    """Get all pending seller registrations"""
    try:
        pending_sellers = User.query.filter_by(role='seller_pending').all()
        return jsonify([user.to_dict() for user in pending_sellers]), 200
    except Exception as e:
        print(f"Error fetching pending sellers: {e}")
        return jsonify([]), 200

@app.route('/api/admin/sellers/<int:user_id>/approve', methods=['PUT'])
@token_required
@admin_required
def approve_seller(current_user, user_id):
    """Approve a seller registration"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        if user.role != 'seller_pending':
            return jsonify({'message': 'User is not a pending seller'}), 400
        
        user.role = 'seller_approved'
        user.can_upload = True
        user.status = 'active'
        
        # Update seller_info with approval
        if user.seller_info:
            user.seller_info['approval_status'] = 'approved'
            user.seller_info['approved_at'] = datetime.utcnow().isoformat()
            user.seller_info['approved_by'] = current_user.username
        
        db.session.commit()
        
        # Send approval email
        try:
            msg = Message(
                "Seller Account Approved - ClassicMotors",
                recipients=[user.email]
            )
            msg.body = f"""
Dear {user.username},

Congratulations! Your seller account has been approved.

You can now upload cars for sale on ClassicMotors.

Business: {user.seller_info.get('business_name', 'N/A') if user.seller_info else 'N/A'}

Log in to your account to start listing your cars.

Thank you for choosing ClassicMotors!
"""
            msg.sender = app.config['MAIL_DEFAULT_SENDER']
            mail.send(msg)
        except Exception as e:
            print(f"Failed to send approval email: {e}")
        
        return jsonify({'message': 'Seller approved successfully', 'user': user.to_dict()}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error approving seller: {e}")
        return jsonify({'message': 'Failed to approve seller'}), 500

@app.route('/api/admin/sellers/<int:user_id>/reject', methods=['PUT'])
@token_required
@admin_required
def reject_seller(current_user, user_id):
    """Reject a seller registration"""
    try:
        user = User.query.get(user_id)
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        if user.role != 'seller_pending':
            return jsonify({'message': 'User is not a pending seller'}), 400
        
        user.role = 'user'
        user.status = 'rejected'
        
        # Update seller_info with rejection
        if user.seller_info:
            user.seller_info['approval_status'] = 'rejected'
            user.seller_info['rejected_at'] = datetime.utcnow().isoformat()
            user.seller_info['rejected_by'] = current_user.username
        
        db.session.commit()
        
        # Send rejection email
        try:
            msg = Message(
                "Seller Application Status - ClassicMotors",
                recipients=[user.email]
            )
            msg.body = f"""
Dear {user.username},

Thank you for your interest in becoming a seller on ClassicMotors.

After review, we regret to inform you that your seller application has been rejected.

Reason: Our team has determined that your application does not meet our current requirements.

You can reapply after 30 days with additional information.

Thank you for your understanding.
"""
            msg.sender = app.config['MAIL_DEFAULT_SENDER']
            mail.send(msg)
        except Exception as e:
            print(f"Failed to send rejection email: {e}")
        
        return jsonify({'message': 'Seller rejected successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error rejecting seller: {e}")
        return jsonify({'message': 'Failed to reject seller'}), 500

# ==================== CONTACT ENDPOINTS ====================

@app.route('/api/contact-us', methods=['POST'])
def contact_us():
    data = request.get_json()
    
    name = data.get('fullName', '')
    email = data.get('email', '')
    phone = data.get('phoneNumber', '')
    subject = data.get('subject', '')
    message = data.get('message', '')
    inquiry_category = data.get('inquiryCategory', 'general')
    
    if not name or not email or not message:
        return jsonify({'message': 'Name, email, and message are required'}), 400
    
    # Save to database
    inquiry = ContactInquiry(
        name=name,
        email=email,
        phone=phone,
        subject=subject,
        message=message,
        inquiry_type=inquiry_category
    )
    db.session.add(inquiry)
    db.session.commit()
    
    # Send email to admin
    try:
        admins = User.query.filter_by(is_admin=True).all()
        admin_emails = [admin.email for admin in admins] if admins else ['admin@classicmotors.co.ke']
        
        msg = Message(
            f"New Contact Form Submission - {inquiry_category}",
            recipients=admin_emails
        )
        msg.body = f"""
New Contact Form Submission

Category: {inquiry_category}
Name: {name}
Email: {email}
Phone: {phone}
Subject: {subject or 'N/A'}

Message:
{message}

Submitted at: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}
"""
        msg.sender = app.config['MAIL_DEFAULT_SENDER']
        mail.send(msg)
        
        # Also send confirmation to user
        user_msg = Message(
            "We've received your inquiry - ClassicMotors",
            recipients=[email]
        )
        user_msg.body = f"""
Dear {name},

Thank you for contacting ClassicMotors!

We have received your inquiry and our team will get back to you within 24 hours.

Your inquiry details:
Category: {inquiry_category}
Subject: {subject or 'N/A'}

We appreciate your interest in ClassicMotors.

Best regards,
ClassicMotors Team
"""
        user_msg.sender = app.config['MAIL_DEFAULT_SENDER']
        mail.send(user_msg)
        
    except Exception as e:
        print(f"Failed to send contact email: {e}")
    
    return jsonify({'message': 'Message sent successfully'}), 200

# ==================== UPLOAD SERVING ====================

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    upload_folder = app.config.get('UPLOAD_FOLDER', 'uploads')
    return send_from_directory(upload_folder, filename)

# ==================== CREATE UPLOAD FOLDER ====================

if not os.path.exists('uploads'):
    os.makedirs('uploads')

if not os.path.exists('static/uploads'):
    os.makedirs('static/uploads')
# Mark product as sold
@app.route('/api/products/<int:product_id>/sold', methods=['PUT'])
@token_required
def mark_product_sold(current_user, product_id):
    """Mark a product as sold"""
    try:
        product = Product.query.get(product_id)
        if not product:
            return jsonify({'message': 'Product not found'}), 404
        
        # Check if user owns the product or is admin
        if product.user_id != current_user.id and not current_user.is_admin:
            return jsonify({'message': 'You do not have permission to mark this car as sold'}), 403
        
        # Check if already sold
        if product.status == 'sold':
            return jsonify({'message': 'This car is already marked as sold'}), 400
        
        # Update product status
        product.status = 'sold'
        product.sold_at = datetime.utcnow()
        product.is_approved = True
        
        db.session.commit()
        
        # Notify admin and seller
        admins = User.query.filter_by(is_admin=True).all()
        seller = User.query.get(product.user_id)
        
        # Notify admins
        for admin in admins:
            try:
                msg = Message(
                    f"Car Sold - {product.name}",
                    recipients=[admin.email]
                )
                msg.body = f"""
Car Sold Notification

Car: {product.name}
Price: KES {product.price}
Sold by: {current_user.username}
Sold at: {product.sold_at.strftime('%Y-%m-%d %H:%M:%S')}

This car has been marked as sold and will be automatically removed from the system after 30 days.
"""
                msg.sender = app.config['MAIL_DEFAULT_SENDER']
                mail.send(msg)
            except Exception as e:
                print(f"Failed to send admin notification: {e}")
        
        # Notify seller (if different from current user)
        if seller and seller.id != current_user.id and seller.email:
            try:
                msg = Message(
                    f"Your Car Has Been Sold - {product.name}",
                    recipients=[seller.email]
                )
                msg.body = f"""
Dear {seller.username},

Congratulations! Your car has been marked as sold.

Car: {product.name}
Price: KES {product.price}
Sold at: {product.sold_at.strftime('%Y-%m-%d %H:%M:%S')}

The car will remain visible as "Sold" for 30 days before being automatically removed.

Thank you for using ClassicMoters!
"""
                msg.sender = app.config['MAIL_DEFAULT_SENDER']
                mail.send(msg)
            except Exception as e:
                print(f"Failed to send seller notification: {e}")
        
        return jsonify({
            'message': 'Car marked as sold successfully',
            'product': product.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Error marking product as sold: {e}")
        return jsonify({'message': 'Failed to mark car as sold'}), 500

# Get sold listings (admin can see all, sellers see their own)
@app.route('/api/user/sold-products', methods=['GET'])
@token_required
def get_sold_products(current_user):
    """Get sold products - admins see all, sellers see their own"""
    try:
        if current_user.is_admin:
            # Admin sees all sold products
            products = Product.query.filter_by(status='sold').order_by(Product.sold_at.desc()).all()
        else:
            # Regular user sees only their sold products
            products = Product.query.filter_by(
                user_id=current_user.id,
                status='sold'
            ).order_by(Product.sold_at.desc()).all()
        
        return jsonify([product.to_dict() for product in products]), 200
    except Exception as e:
        print(f"Error fetching sold products: {e}")
        return jsonify([]), 200

# Auto-delete sold products after 30 days (run as scheduled task)
def cleanup_sold_products():
    """Delete sold products that are older than 30 days"""
    with app.app_context():
        try:
            thirty_days_ago = datetime.utcnow() - timedelta(days=30)
            sold_products = Product.query.filter(
                Product.status == 'sold',
                Product.sold_at <= thirty_days_ago
            ).all()
            
            deleted_count = 0
            for product in sold_products:
                # Delete images
                all_images = [product.image_path]
                if product.extra_images:
                    all_images.extend(product.extra_images.split(','))
                for image in all_images:
                    if image:
                        file_path = os.path.join(app.config['UPLOAD_FOLDER'], image)
                        if os.path.exists(file_path):
                            try:
                                os.remove(file_path)
                            except:
                                pass
                
                # Notify seller before deletion
                seller = User.query.get(product.user_id)
                if seller and seller.email:
                    try:
                        msg = Message(
                            f"Your Sold Car Has Been Removed - {product.name}",
                            recipients=[seller.email]
                        )
                        msg.body = f"""
Dear {seller.username},

Your car "{product.name}" has been automatically removed from ClassicMoters as it was sold over 30 days ago.

Car: {product.name}
Price: KES {product.price}
Sold at: {product.sold_at.strftime('%Y-%m-%d %H:%M:%S')}

Thank you for using ClassicMoters!
"""
                        msg.sender = app.config['MAIL_DEFAULT_SENDER']
                        mail.send(msg)
                    except Exception as e:
                        print(f"Failed to send deletion notification: {e}")
                
                db.session.delete(product)
                deleted_count += 1
            
            db.session.commit()
            print(f"Cleaned up {deleted_count} sold cars older than 30 days")
            return deleted_count
        except Exception as e:
            print(f"Error cleaning up sold products: {e}")
            db.session.rollback()
            return 0

# Endpoint to trigger manual cleanup (admin only)
@app.route('/api/admin/cleanup-sold', methods=['POST'])
@token_required
@admin_required
def trigger_cleanup(current_user):
    """Admin endpoint to manually trigger cleanup of sold cars"""
    try:
        deleted_count = cleanup_sold_products()
        return jsonify({
            'message': f'Successfully cleaned up {deleted_count} sold cars',
            'deleted_count': deleted_count
        }), 200
    except Exception as e:
        print(f"Error in cleanup: {e}")
        return jsonify({'message': 'Failed to cleanup sold cars'}), 500
# ==================== RUN APP ====================

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)