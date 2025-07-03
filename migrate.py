from app import app, db, migrate

if __name__ == '__main__':
    with app.app_context():
        migrate.init_app(app, db)
    print("Migration setup complete.")
    print("Run the following commands to create and apply migrations:")
    print("1. flask db init")
    print("2. flask db migrate -m 'Add allergy and created_at to patient'")
    print("3. flask db upgrade")
