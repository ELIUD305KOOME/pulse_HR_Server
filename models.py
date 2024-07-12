from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import MetaData
from sqlalchemy.orm import validates
from sqlalchemy_serializer import SerializerMixin
from datetime import datetime
import random
import re
from passlib.hash import bcrypt_sha256
from sqlalchemy.ext.hybrid import hybrid_property


metadata = MetaData(
    naming_convention={
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    }
)

db = SQLAlchemy(metadata=metadata)

class UserRole:
    EMPLOYEE = 'employee'
    ADMIN = 'admin'

class User(db.Model, SerializerMixin):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(150), nullable=False)
    lastname = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    _password = db.Column('password', db.String(150), nullable=False)  # Rename to avoid conflict with method name
    role = db.Column(db.String(20), default=UserRole.EMPLOYEE)
    time_entries = db.relationship('TimeEntry', backref='user', lazy=True)
    leaves = db.relationship('LeaveRequest', backref='user', lazy=True)
    # activity_logs = db.relationship('ActivityLog', backref='user', lazy=True)
    schedules = db.relationship('Schedule', primaryjoin="User.id == Schedule.user_id")

    def __repr__(self):
        return f"<User id={self.id}, firstname={self.firstname}, lastname={self.lastname}, email={self.email}, role={self.role}>"

    @hybrid_property
    def password(self):
        return self._password
    
    @password.setter
    def password(self, plaintext_password):
        self._password = bcrypt_sha256.hash(plaintext_password)

    def check_password(self, plaintext_password):
        return bcrypt_sha256.verify(plaintext_password, self._password)
    
    @classmethod
    def authenticate(cls, email, password, role):
        user = cls.query.filter_by(email=email).first()
        if user and user.role == role.lower() and user.check_password(password):
            return user
        return None
    
    
    @validates('email')
    def validate_email(self, key, email):
        if not email:
            raise ValueError("Email is required")
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("Invalid email format")

        existing_user = User.query.filter(User.email == email).first()
        if existing_user and existing_user.id != self.id:
            raise ValueError("Email address is already registered")

        return email.lower()

    @validates('password')
    def validate_password(self, key, password):
        if not password:
            raise ValueError("Password is required")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long")
        return password

    def to_dict(self):
        return {
            'id': self.id,
            'firstname': self.firstname,
            'lastname': self.lastname,
            'email': self.email,
            'role': self.role,
            'time_entries': [time_entry.to_dict() for time_entry in self.time_entries],
            'leaves': [leave.to_dict() for leave in self.leaves],
            # 'activity_logs': [activity_log.to_dict() for activity_log in self.activity_logs],
        }



class ActivityLog(db.Model, SerializerMixin):
    __tablename__ = 'activity_log'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Nullable if action is system-level
    user = db.relationship('User', backref='activity_logs')  # 'activity_logs' is plural
    user_firstname = db.Column(db.String(150), nullable=True)
    user_lastname = db.Column(db.String(150), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<ActivityLog id={self.id}, user_id={self.user_id}, user_firstname={self.user_firstname}, user_lastname={self.user_lastname}, action='{self.action}', timestamp={self.timestamp}>"

    # to_dict method remains as before
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'user_firstname': self.user.firstname if self.user else self.user_firstname,
            'user_lastname': self.user.lastname if self.user else self.user_lastname,
            'action': self.action,
            'timestamp': self.timestamp.isoformat(),
        }

class Admin(db.Model, SerializerMixin):
    __tablename__ = 'admin'
    

    id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    user = db.relationship("User", backref="admin")
    leaves = db.relationship('LeaveRequest', backref='admin', lazy=True)


class Employee(db.Model, SerializerMixin):
    __tablename__ = 'employee'
    

    id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    user = db.relationship("User", backref="employee")
    employee_id = db.Column(db.Integer, unique=True)
    leaves = db.relationship('LeaveRequest', backref='employee', lazy=True)
    schedules = db.relationship('Schedule', backref='employee', lazy=True)

    def assign_random_schedule(self):
        # Example of random selection logic; adjust as needed
        available_schedules = Schedule.query.all()
        random_schedule = random.choice(available_schedules)
        self.schedules.append(random_schedule)


class TimeEntry(db.Model):
    __tablename__ = 'time_entry'
    

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    arrivaltime = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"<TimeEntry user_id={self.user_id}, arrivaltime={self.arrivaltime}, timestamp={self.timestamp}>"


class LeaveRequest(db.Model, SerializerMixin):
    __tablename__ = 'leave_request'
    

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    reason = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')  # 'pending', 'approved', 'denied'
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'start_date': self.start_date,
            'end_date': self.end_date,
            'reason': self.reason,
            'status': self.status,
            'created_at': self.created_at
        }


class Schedule(db.Model):
    __tablename__ = 'schedule'
    

    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'), nullable=False)
    shift = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


    def __repr__(self):
        return f"<Schedule id={self.id}, employee_id={self.employee_id}, shift={self.shift}>"


if __name__ == "__main__":
    db.create_all()
    print("Database schema created successfully")
