#!/usr/bin/env python3
"""
Database setup script for NightHosting Panel
Run this if you have database initialization issues
"""

import os
import sqlite3
from flask import Flask
from models import db, User, Instance, init_db

def setup_database():
    """Setup database with proper error handling"""
    
    # Create Flask app
    app = Flask(__name__)
    
    # Ensure absolute path for database
    basedir = os.path.abspath(os.path.dirname(__file__))
    data_dir = os.path.join(basedir, 'data')
    db_path = os.path.join(data_dir, 'db.sqlite3')
    
    print(f"Setting up database at: {db_path}")
    
    # Create directories
    os.makedirs(data_dir, exist_ok=True)
    os.makedirs(os.path.join(basedir, 'user_data'), exist_ok=True)
    
    # Set permissions
    os.chmod(data_dir, 0o755)
    
    # Configure Flask app
    app.config['SECRET_KEY'] = 'nighthosting-secret-key'
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize database
    db.init_app(app)
    
    with app.app_context():
        try:
            # Test database connection
            print("Testing database connection...")
            conn = sqlite3.connect(db_path)
            conn.close()
            print("✅ Database connection successful")
            
            # Create tables
            print("Creating database tables...")
            db.create_all()
            print("✅ Database tables created")
            
            # Create default admin user if no users exist
            if User.query.count() == 0:
                print("Creating default admin user...")
                admin_user = User(
                    username='admin',
                    email='admin@nighthosting.local',
                    password='admin123'
                )
                db.session.add(admin_user)
                db.session.commit()
                print("✅ Default admin user created (admin/admin123)")
            else:
                print("✅ Users already exist in database")
            
            print("\n🎉 Database setup completed successfully!")
            print("You can now run: python3 app.py")
            
        except Exception as e:
            print(f"❌ Database setup failed: {e}")
            print(f"Database path: {db_path}")
            print(f"Data directory: {data_dir}")
            print(f"Data directory exists: {os.path.exists(data_dir)}")
            print(f"Data directory permissions: {oct(os.stat(data_dir).st_mode)[-3:]}")
            return False
    
    return True

if __name__ == '__main__':
    setup_database()