"""Initialize the database."""
from app import app, db, User
from werkzeug.security import generate_password_hash

def init_db():
    """Initialize the database."""
    with app.app_context():
        # Create all database tables
        db.create_all()
        
        # Create admin user if it doesn't exist
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                name='Administrator',
                role='admin',
                email='admin@example.com',
                phone='0000000000',
                password_hash=generate_password_hash('admin123')
            )
            db.session.add(admin)
            db.session.commit()
            print("Created admin user")
        
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db()
