from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import uuid

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    google_id = db.Column(db.String(100), unique=True, nullable=True)
    profile_picture = db.Column(db.String(500), nullable=True)
    phone_number = db.Column(db.String(20), nullable=True)
    role = db.Column(db.String(50), default='user')
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    can_upload = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    seller_info = db.Column(db.JSON, nullable=True)
    
    # Relationships - specify foreign_keys to avoid ambiguity
    products = db.relationship('Product', foreign_keys='Product.user_id', backref='seller', lazy=True, cascade='all, delete-orphan')
    reviews = db.relationship('Review', backref='user', lazy=True, cascade='all, delete-orphan')
    favorites = db.relationship('Favorite', backref='user', lazy=True, cascade='all, delete-orphan')
    # For approved_by relationship
    approved_products = db.relationship('Product', foreign_keys='Product.approved_by', backref='approver', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def is_seller(self):
        return self.can_upload or self.role in ['admin', 'seller_approved']

    def is_pending_seller(self):
        return self.role == 'seller_pending'

    def is_approved_seller(self):
        return self.role == 'seller_approved' or self.can_upload

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "profile_picture": self.profile_picture,
            "phone_number": self.phone_number,
            "role": self.role,
            "is_admin": self.is_admin,
            "can_upload": self.can_upload,
            "is_verified": self.is_verified,
            "status": self.status,
            "is_seller": self.is_seller(),
            "is_pending_seller": self.is_pending_seller(),
            "seller_info": self.seller_info,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None
        }


class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    image_path = db.Column(db.String(255))
    extra_images = db.Column(db.Text)
    
    # Car specific fields
    brand = db.Column(db.String(100), nullable=True)
    year = db.Column(db.Integer, nullable=True)
    mileage = db.Column(db.String(50), nullable=True)
    fuel = db.Column(db.String(50), nullable=True)
    transmission = db.Column(db.String(50), nullable=True)
    location = db.Column(db.String(100), nullable=True)
    color = db.Column(db.String(50), nullable=True)
    condition = db.Column(db.String(50), default='Used')
    
    # Product metadata
    category = db.Column(db.String(50))
    is_approved = db.Column(db.Boolean, default=False)
    is_featured = db.Column(db.Boolean, default=False)
    views = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default='pending')
    
    # Seller info
    seller_name = db.Column(db.String(100), nullable=True)
    seller_phone = db.Column(db.String(20), nullable=True)
    
    # Foreign keys - explicit for clarity
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    approved_at = db.Column(db.DateTime, nullable=True)
    sold_at = db.Column(db.DateTime, nullable=True)
    scheduled_deletion_at = db.Column(db.DateTime, nullable=True)  # NEW: When this sold car should be deleted
    
    # Relationships
    reviews = db.relationship('Review', backref='product', lazy=True, cascade='all, delete-orphan')
    favorites = db.relationship('Favorite', backref='product', lazy=True, cascade='all, delete-orphan')
    
    def mark_as_sold(self):
        """Mark product as sold and schedule deletion after 30 days"""
        self.status = 'sold'
        self.sold_at = datetime.utcnow()
        self.scheduled_deletion_at = datetime.utcnow() + timedelta(days=30)
        self.is_approved = True
        return self.scheduled_deletion_at
    
    def is_scheduled_for_deletion(self):
        """Check if product is scheduled for deletion"""
        if not self.scheduled_deletion_at:
            return False
        return datetime.utcnow() >= self.scheduled_deletion_at
    
    def days_until_deletion(self):
        """Get days remaining until deletion"""
        if not self.scheduled_deletion_at:
            return None
        delta = self.scheduled_deletion_at - datetime.utcnow()
        return max(0, delta.days)
    
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "price": self.price,
            "image_path": self.image_path,
            "extra_images": self.extra_images.split(',') if self.extra_images else [],
            "brand": self.brand,
            "year": self.year,
            "mileage": self.mileage,
            "fuel": self.fuel,
            "transmission": self.transmission,
            "location": self.location,
            "color": self.color,
            "condition": self.condition,
            "category": self.category,
            "is_approved": self.is_approved,
            "is_featured": self.is_featured,
            "views": self.views,
            "status": self.status,
            "seller_name": self.seller_name,
            "seller_phone": self.seller_phone,
            "user_id": self.user_id,
            "approved_by": self.approved_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "approved_at": self.approved_at.isoformat() if self.approved_at else None,
            "sold_at": self.sold_at.isoformat() if self.sold_at else None,
            "scheduled_deletion_at": self.scheduled_deletion_at.isoformat() if self.scheduled_deletion_at else None,
            "days_until_deletion": self.days_until_deletion(),
            "rating": self.get_average_rating(),
            "review_count": len(self.reviews) if self.reviews else 0
        }
    
    def get_average_rating(self):
        if not self.reviews:
            return 0
        total = sum(r.rating for r in self.reviews)
        return round(total / len(self.reviews), 1)


class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user_name = db.Column(db.String(80), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'product_id': self.product_id,
            'user_id': self.user_id,
            'user_name': self.user_name,
            'rating': self.rating,
            'comment': self.comment,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class Favorite(db.Model):
    __tablename__ = 'favorites'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "product_id": self.product_id,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "otp": self.otp,
            "expiry": self.expiry.isoformat() if self.expiry else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class ContactInquiry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    phone = db.Column(db.String(20), nullable=True)
    subject = db.Column(db.String(200), nullable=True)
    message = db.Column(db.Text, nullable=False)
    inquiry_type = db.Column(db.String(50), default='general')
    status = db.Column(db.String(20), default='unread')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "phone": self.phone,
            "subject": self.subject,
            "message": self.message,
            "inquiry_type": self.inquiry_type,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }