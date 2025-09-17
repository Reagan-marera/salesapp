from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    can_upload = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_admin": self.is_admin,
            "can_upload": self.can_upload,
            "is_verified": self.is_verified
        }

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    image_path = db.Column(db.String(255))  # Main image
    extra_images = db.Column(db.Text)      # Comma-separated list of extra image paths
    category = db.Column(db.String(50))
    is_approved = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "price": self.price,
            "image_path": self.image_path,
            "extra_images": self.extra_images.split(',') if self.extra_images else [],
            "category": self.category,
            "is_approved": self.is_approved,
            "user_id": self.user_id
        }

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), default="pending")
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "product_id": self.product_id,
            "user_id": self.user_id,
            "phone_number": self.phone_number,
            "email": self.email,
            "location": self.location,
            "status": self.status,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }

class Payment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    amount = db.Column(db.Float, nullable=False)
    transaction_id = db.Column(db.String(100), unique=True, default=lambda: str(uuid.uuid4()))
    status = db.Column(db.String(20), default="pending")
    payment_method = db.Column(db.String(50))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "amount": self.amount,
            "transaction_id": self.transaction_id,
            "status": self.status,
            "payment_method": self.payment_method,
            "user_id": self.user_id,
            "product_id": self.product_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None
        }
class OTP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), nullable=False)
    otp = db.Column(db.String(6), nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)

