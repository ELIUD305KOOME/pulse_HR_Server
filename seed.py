from app import app
from datetime import datetime
from models import db, User

def seed_database():
    with app.app_context():
        try:
            print("Creating users...")
            users = [
                User(firstname='John', lastname='Doe', email='john.doe@example.com', password='password123', role='admin'),
                User(firstname='Jane', lastname='Smith', email='jane.smith@example.com', password='password123', role='employee'),
                User(firstname='Alice', lastname='Johnson', email='alice.johnson@example.com', password='password123', role='employee'),
                User(firstname='Bob', lastname='Brown', email='bob.brown@example.com', password='password123', role='admin')
                
            ]

            db.session.bulk_save_objects(users)
            
            db.session.commit()

            print("Database seeded successfully!")
        except Exception as e:
            print(f"Error seeding database: {e}")
            db.session.rollback()

if __name__ == "__main__":
    seed_database()
