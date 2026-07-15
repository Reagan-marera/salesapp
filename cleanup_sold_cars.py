from app import app
from models import db, Product
from datetime import datetime, timedelta
import os

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
                
                db.session.delete(product)
                deleted_count += 1
            
            db.session.commit()
            print(f"Cleaned up {deleted_count} sold cars older than 30 days")
            return deleted_count
        except Exception as e:
            print(f"Error cleaning up sold products: {e}")
            db.session.rollback()
            return 0

if __name__ == '__main__':
    cleanup_sold_products()