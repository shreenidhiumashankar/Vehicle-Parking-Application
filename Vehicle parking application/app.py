from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key'  # Change to a secure key
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///parking.db'
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'connect_args': {'check_same_thread': False}}

db = SQLAlchemy(app)

# Admin secret key for registration - change this securely
ADMIN_REGISTRATION_SECRET = 'adminsecret123'

# Models

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'admin' or 'user'
    reservations = db.relationship('Reservation', backref='user', lazy=True)

class ParkingLot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    price_per_hour = db.Column(db.Float, nullable=False)
    address = db.Column(db.String(200), nullable=False)
    pin_code = db.Column(db.String(10), nullable=False)
    max_spots = db.Column(db.Integer, nullable=False)
    parking_spots = db.relationship('ParkingSpot', backref='parking_lot', lazy=True, cascade='all, delete-orphan')

class ParkingSpot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    lot_id = db.Column(db.Integer, db.ForeignKey('parking_lot.id'), nullable=False)
    spot_number = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(1), nullable=False, default='A')  # 'A' - Available, 'O' - Occupied
    reservation = db.relationship('Reservation', backref='parking_spot', uselist=False, cascade='all, delete-orphan')

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    spot_id = db.Column(db.Integer, db.ForeignKey('parking_spot.id'), nullable=False, unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    parking_timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    leaving_timestamp = db.Column(db.DateTime)
    parking_cost = db.Column(db.Float)
    active = db.Column(db.Boolean, default=True)

# Decorator for login and role verification
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please login first.')
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash('Access denied.')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Initialize DB with tables
def init_db():
    with app.app_context():
        db.create_all()

# Routes

@app.route('/')
def index():
    # Landing page with links to login and registration (see templates section)
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        role = request.form.get('role')
        admin_secret = request.form.get('admin_secret', '').strip()

        if not username or not password or not confirm_password or not role:
            flash('Please fill all required fields.')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return render_template('register.html')

        if role not in ['admin', 'user']:
            flash('Invalid role selected.')
            return render_template('register.html')

        # If admin role selected, verify secret key
        if role == 'admin':
            if admin_secret != ADMIN_REGISTRATION_SECRET:
                flash('Invalid admin registration secret.')
                return render_template('register.html')

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        if not username or not password:
            flash('Please enter both username and password.')
            return render_template('login.html')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash(f'Welcome, {user.username}!')
            # Redirect based on role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid credentials.')
            return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

# Admin Views

@app.route('/admin/dashboard')
@login_required('admin')
def admin_dashboard():
    parking_lots = ParkingLot.query.all()
    users = User.query.filter(User.role=='user').all()
    total_spots = sum(lot.max_spots for lot in parking_lots)
    occupied_spots = ParkingSpot.query.filter_by(status='O').count()
    return render_template('admin_dashboard.html', parking_lots=parking_lots, users=users,
                           total_spots=total_spots, occupied_spots=occupied_spots)

@app.route('/admin/create_lot', methods=['GET', 'POST'])
@login_required('admin')
def create_lot():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        price_per_hour = request.form.get('price_per_hour', '').strip()
        address = request.form.get('address', '').strip()
        pin_code = request.form.get('pin_code', '').strip()
        max_spots = request.form.get('max_spots', '').strip()

        if not (name and price_per_hour and address and pin_code and max_spots):
            flash('All fields are required.')
            return render_template('create_lot.html')

        if ParkingLot.query.filter_by(name=name).first():
            flash('Parking lot name already exists.')
            return render_template('create_lot.html')

        try:
            price_per_hour = float(price_per_hour)
            max_spots = int(max_spots)
        except ValueError:
            flash('Price must be a number and Max spots must be an integer.')
            return render_template('create_lot.html')

        lot = ParkingLot(name=name, price_per_hour=price_per_hour, address=address, pin_code=pin_code, max_spots=max_spots)
        db.session.add(lot)
        db.session.commit()

        # Create parking spots for this lot
        for i in range(1, max_spots + 1):
            spot = ParkingSpot(lot_id=lot.id, spot_number=i, status='A')
            db.session.add(spot)
        db.session.commit()

        flash('Parking lot created successfully.')
        return redirect(url_for('admin_dashboard'))

    return render_template('create_lot.html')

@app.route('/admin/edit_lot/<int:lot_id>', methods=['GET', 'POST'])
@login_required('admin')
def edit_lot(lot_id):
    lot = ParkingLot.query.get_or_404(lot_id)
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        price_per_hour = request.form.get('price_per_hour', '').strip()
        address = request.form.get('address', '').strip()
        pin_code = request.form.get('pin_code', '').strip()
        max_spots = request.form.get('max_spots', '').strip()

        # Validation checks
        if not (name and price_per_hour and address and pin_code and max_spots):
            flash('All fields required.')
            return render_template('edit_lot.html', lot=lot)

        if ParkingLot.query.filter(ParkingLot.name==name, ParkingLot.id!=lot_id).first():
            flash('Another lot with this name exists.')
            return render_template('edit_lot.html', lot=lot)

        try:
            price_per_hour = float(price_per_hour)
            max_spots = int(max_spots)
        except ValueError:
            flash('Price and max spots must be valid numbers.')
            return render_template('edit_lot.html', lot=lot)

        occupied_count = ParkingSpot.query.filter_by(lot_id=lot.id, status='O').count()
        if max_spots < occupied_count:
            flash(f'Cannot reduce max spots below currently occupied spots ({occupied_count}).')
            return render_template('edit_lot.html', lot=lot)

        lot.name = name
        lot.price_per_hour = price_per_hour
        lot.address = address
        lot.pin_code = pin_code

        if max_spots != lot.max_spots:
            if max_spots > lot.max_spots:
                # Add spots
                for i in range(lot.max_spots + 1, max_spots + 1):
                    db.session.add(ParkingSpot(lot_id=lot.id, spot_number=i, status='A'))
            else:
                # Remove available spots with number > max_spots
                to_remove = ParkingSpot.query.filter_by(lot_id=lot.id).filter(ParkingSpot.spot_number > max_spots).all()
                for spot in to_remove:
                    if spot.status == 'O':
                        flash('Cannot remove occupied spot.')
                        return render_template('edit_lot.html', lot=lot)
                    db.session.delete(spot)
            lot.max_spots = max_spots

        db.session.commit()
        flash('Parking lot updated.')
        return redirect(url_for('admin_dashboard'))

    return render_template('edit_lot.html', lot=lot)

@app.route('/admin/delete_lot/<int:lot_id>', methods=['POST'])
@login_required('admin')
def delete_lot(lot_id):
    lot = ParkingLot.query.get_or_404(lot_id)
    occupied_count = ParkingSpot.query.filter_by(lot_id=lot.id, status='O').count()
    if occupied_count > 0:
        flash('Cannot delete lot while spots are occupied.')
        return redirect(url_for('admin_dashboard'))
    db.session.delete(lot)
    db.session.commit()
    flash('Parking lot deleted.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/spot_status/<int:lot_id>')
@login_required('admin')
def spot_status(lot_id):
    lot = ParkingLot.query.get_or_404(lot_id)
    spots = ParkingSpot.query.filter_by(lot_id=lot.id).order_by(ParkingSpot.spot_number).all()
    return render_template('spot_status.html', lot=lot, spots=spots)

@app.route('/admin/users')
@login_required('admin')
def all_users():
    users = User.query.filter_by(role='user').all()
    return render_template('all_users.html', users=users)

# User Views

@app.route('/user/dashboard')
@login_required('user')
def user_dashboard():
    user = User.query.get(session['user_id'])
    active_reservation = Reservation.query.filter_by(user_id=user.id, active=True).first()
    past_reservations = Reservation.query.filter_by(user_id=user.id, active=False).order_by(Reservation.parking_timestamp.desc()).all()
    return render_template('user_dashboard.html', user=user, active_reservation=active_reservation,
                           past_reservations=past_reservations)

@app.route('/user/book', methods=['GET', 'POST'])
@login_required('user')
def book_spot():
    user = User.query.get(session['user_id'])

    if Reservation.query.filter_by(user_id=user.id, active=True).first():
        flash('You already have an active booking.')
        return redirect(url_for('user_dashboard'))

    parking_lots = ParkingLot.query.all()
    if not parking_lots:
        flash('No parking lots available. Please try later.')
        return redirect(url_for('user_dashboard'))

    any_available = any(
        ParkingSpot.query.filter_by(lot_id=lot.id, status='A').first()
        for lot in parking_lots
    )
    if not any_available:
        flash('No available spots currently.')
        return redirect(url_for('user_dashboard'))

    if request.method == 'POST':
        lot_id = request.form.get('lot_id', type=int)
        if not lot_id:
            flash('Select a parking lot.')
            return render_template('book_spot.html', parking_lots=parking_lots)

        lot = ParkingLot.query.get_or_404(lot_id)
        spot = ParkingSpot.query.filter_by(lot_id=lot.id, status='A').order_by(ParkingSpot.spot_number).first()
        if not spot:
            flash('No available spots in this lot.')
            return render_template('book_spot.html', parking_lots=parking_lots)

        spot.status = 'O'
        reservation = Reservation(spot_id=spot.id, user_id=user.id, parking_timestamp=datetime.utcnow(), active=True)
        db.session.add(reservation)
        db.session.commit()

        flash(f'Spot #{spot.spot_number} booked successfully in {lot.name}.')
        return redirect(url_for('user_dashboard'))

    return render_template('book_spot.html', parking_lots=parking_lots)

@app.route('/user/release/<int:reservation_id>', methods=['POST'])
@login_required('user')
def release_spot(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    if reservation.user_id != session['user_id']:
        flash('Unauthorized action.')
        return redirect(url_for('user_dashboard'))
    if not reservation.active:
        flash('Spot already released.')
        return redirect(url_for('user_dashboard'))

    leave_time = datetime.utcnow()
    duration = (leave_time - reservation.parking_timestamp).total_seconds() / 3600
    lot = reservation.parking_spot.parking_lot
    cost = round(duration * lot.price_per_hour, 2)

    reservation.leaving_timestamp = leave_time
    reservation.parking_cost = cost
    reservation.active = False

    reservation.parking_spot.status = 'A'

    db.session.commit()

    flash(f'Spot released. Duration: {duration:.2f} hrs, Cost: ₹{cost}.')
    return redirect(url_for('user_dashboard'))

# 404 Error Handler
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
