import os
import sqlite3
import zipfile
import io
import hashlib
import json
import csv
from datetime import datetime
from functools import wraps
from typing import Optional, List, Dict, Any
import requests
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from flask import Flask, request, jsonify, send_file, make_response
from flask_restx import Api, Resource, fields, Namespace, abort
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import Unauthorized
from dotenv import load_dotenv
from rapidfuzz import fuzz, process
import base64

# Load environment variables
load_dotenv('transport_api_key.env')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['RESTX_MASK_SWAGGER'] = False
app.config['ERROR_INCLUDE_MESSAGE'] = False
CORS(app)

# Initialize API
authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': 'Add a JWT token to the header with ** Bearer &lt;JWT&gt; ** token to authorize'
    }
}

api = Api(app, 
          version='1.0',
          title='Sydney Bus Network API',
          description='RESTful API for managing Sydney bus network data with role-based access control',
          doc='/swagger',
          default='General',
          default_label='General Operations',
          authorizations=authorizations,
          security='Bearer Auth')

# Database configuration
DB_FILE = 'z5540213.sqlite'
TRANSPORT_API_KEY = os.getenv('TRANSPORT_API_KEY')
TRANSPORT_API_BASE_URL = 'https://api.transport.nsw.gov.au/v1/gtfs/schedule'

# Namespaces
auth_ns = api.namespace('auth', description='Authentication operations')
users_ns = api.namespace('users', description='User management operations (Admin only)')
agencies_ns = api.namespace('agencies', description='Bus agency data import operations')
routes_ns = api.namespace('routes', description='Bus route operations')
stops_ns = api.namespace('stops', description='Bus stop operations')
trips_ns = api.namespace('trips', description='Bus trip operations')
favourites_ns = api.namespace('favourites', description='Favourite routes management')
visualisation_ns = api.namespace('visualisation', description='Data visualization and export')

# ============================================================================
# Models for Swagger documentation
# ============================================================================

# User models
user_model = api.model('User', {
    'id': fields.Integer(description='User ID'),
    'username': fields.String(required=True, description='Username'),
    'role': fields.String(required=True, description='User role (Admin/Planner/Commuter)'),
    'is_active': fields.Boolean(description='User active status'),
    'created_at': fields.String(description='User creation timestamp')
})

user_create_model = api.model('UserCreate', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password'),
    'role': fields.String(required=True, description='User role (Planner/Commuter)')
})

user_login_model = api.model('UserLogin', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password')
})

user_update_model = api.model('UserUpdate', {
    'is_active': fields.Boolean(required=True, description='User active status')
})

# Agency models
agency_import_model = api.model('AgencyImport', {
    'agency_id': fields.String(required=True, description='Agency ID (e.g., GSBC001 or SBSC006)')
})

# Route models
route_model = api.model('Route', {
    'route_id': fields.String(description='Route ID'),
    'route_short_name': fields.String(description='Route short name'),
    'route_long_name': fields.String(description='Route long name'),
    'route_type': fields.String(description='Route type'),
    'agency_id': fields.String(description='Agency ID')
})

# Stop models
stop_model = api.model('Stop', {
    'stop_id': fields.String(description='Stop ID'),
    'stop_name': fields.String(description='Stop name'),
    'stop_lat': fields.Float(description='Stop latitude'),
    'stop_lon': fields.Float(description='Stop longitude'),
    'zone_id': fields.String(description='Zone ID'),
    'stop_url': fields.String(description='Stop URL')
})

stop_search_model = api.model('StopSearch', {
    'query': fields.String(required=True, description='Search query for stop name')
})

# Trip models
trip_model = api.model('Trip', {
    'trip_id': fields.String(description='Trip ID'),
    'route_id': fields.String(description='Route ID'),
    'service_id': fields.String(description='Service ID'),
    'trip_headsign': fields.String(description='Trip headsign'),
    'direction_id': fields.Integer(description='Direction ID'),
    'shape_id': fields.String(description='Shape ID')
})

# Favourite models
favourite_model = api.model('Favourite', {
    'id': fields.Integer(description='Favourite ID'),
    'user_id': fields.Integer(description='User ID'),
    'route_id': fields.String(description='Route ID'),
    'created_at': fields.String(description='Creation timestamp')
})

favourite_create_model = api.model('FavouriteCreate', {
    'route_id': fields.String(required=True, description='Route ID to add to favourites')
})

# Pagination models
pagination_parser = api.parser()
pagination_parser.add_argument('page', type=int, default=1, help='Page number')
pagination_parser.add_argument('per_page', type=int, default=20, help='Items per page')

# ============================================================================
# Database initialization and helper functions
# ============================================================================

def init_database():
    """Initialize SQLite database with required tables and default users."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('Admin', 'Planner', 'Commuter')),
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create agencies table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS agencies (
            agency_id TEXT PRIMARY KEY,
            agency_name TEXT,
            agency_url TEXT,
            agency_timezone TEXT,
            agency_lang TEXT,
            agency_phone TEXT,
            imported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create routes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS routes (
            route_id TEXT PRIMARY KEY,
            agency_id TEXT,
            route_short_name TEXT,
            route_long_name TEXT,
            route_desc TEXT,
            route_type INTEGER,
            route_url TEXT,
            route_color TEXT,
            route_text_color TEXT,
            FOREIGN KEY (agency_id) REFERENCES agencies (agency_id)
        )
    ''')
    
    # Create stops table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stops (
            stop_id TEXT PRIMARY KEY,
            stop_code TEXT,
            stop_name TEXT,
            stop_desc TEXT,
            stop_lat REAL,
            stop_lon REAL,
            zone_id TEXT,
            stop_url TEXT,
            location_type INTEGER,
            parent_station TEXT,
            stop_timezone TEXT,
            wheelchair_boarding INTEGER
        )
    ''')
    
    # Create trips table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS trips (
            trip_id TEXT PRIMARY KEY,
            route_id TEXT,
            service_id TEXT,
            trip_headsign TEXT,
            trip_short_name TEXT,
            direction_id INTEGER,
            block_id TEXT,
            shape_id TEXT,
            wheelchair_accessible INTEGER,
            bikes_allowed INTEGER,
            FOREIGN KEY (route_id) REFERENCES routes (route_id)
        )
    ''')
    
    # Create stop_times table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stop_times (
            trip_id TEXT,
            arrival_time TEXT,
            departure_time TEXT,
            stop_id TEXT,
            stop_sequence INTEGER,
            stop_headsign TEXT,
            pickup_type INTEGER,
            drop_off_type INTEGER,
            shape_dist_traveled REAL,
            PRIMARY KEY (trip_id, stop_sequence),
            FOREIGN KEY (trip_id) REFERENCES trips (trip_id),
            FOREIGN KEY (stop_id) REFERENCES stops (stop_id)
        )
    ''')
    
    # Create shapes table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shapes (
            shape_id TEXT,
            shape_pt_lat REAL,
            shape_pt_lon REAL,
            shape_pt_sequence INTEGER,
            shape_dist_traveled REAL,
            PRIMARY KEY (shape_id, shape_pt_sequence)
        )
    ''')
    
    # Create favourites table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS favourites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            route_id TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (route_id) REFERENCES routes (route_id),
            UNIQUE(user_id, route_id)
        )
    ''')
    
    # Create default users if they don't exist
    default_users = [
        ('admin', 'admin', 'Admin'),
        ('commuter', 'commuter', 'Commuter'),
        ('planner', 'planner', 'Planner')
    ]
    
    for username, password, role in default_users:
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if not cursor.fetchone():
            password_hash = generate_password_hash(password)
            cursor.execute('''
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
            ''', (username, password_hash, role))
    
    conn.commit()
    conn.close()

# ============================================================================
# Authentication and Authorization
# ============================================================================

def generate_token(user_id: int) -> str:
    """Generate a unique session token."""
    return hashlib.sha256(f"{user_id}{datetime.now()}".encode()).hexdigest()

def get_current_user():
    """Get the current authenticated user from token."""
    token = request.headers.get('Authorization')
    if not token:
        return None
    
    if token.startswith('Bearer '):
        token = token[7:]
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT u.* FROM users u
        JOIN sessions s ON u.id = s.user_id
        WHERE s.token = ? AND u.is_active = 1
    ''', (token,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {
            'id': user[0],
            'username': user[1],
            'role': user[3],
            'is_active': user[4]
        }
    return None

def require_auth(allowed_roles: List[str] = None):
    """Decorator to require authentication and check role permissions."""
    def decorator(f):
        @wraps(f)
        @api.doc(security='Bearer Auth')
        def decorated_function(*args, **kwargs):
            user = get_current_user()
            if not user:
                abort(401, 'Authentication required')
            
            if allowed_roles and user['role'] not in allowed_roles:
                abort(403, 'Insufficient permissions')
            
            request.current_user = user
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ============================================================================
# Authentication Endpoints
# ============================================================================

@auth_ns.route('/login')
class Login(Resource):
    @api.expect(user_login_model)
    @api.response(200, 'Login successful')
    @api.response(401, 'Invalid credentials')
    def post(self):
        """Login with username and password."""
        data = request.json
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            abort(400, 'Username and password required')
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            abort(401, 'Invalid credentials')
        
        # Check password
        if not check_password_hash(user[2], password):
            conn.close()
            abort(401, 'Invalid credentials')
        
        # Check if user is active (user[4] is the is_active field)
        if not user[4]:
            conn.close()
            abort(403, 'Account is deactivated')
        
        # Create session token
        token = generate_token(user[0])
        cursor.execute('''
            INSERT INTO sessions (user_id, token)
            VALUES (?, ?)
        ''', (user[0], token))
        conn.commit()
        conn.close()
        
        return {
            'token': token,
            'user': {
                'id': user[0],
                'username': user[1],
                'role': user[3]
            }
        }, 200

@auth_ns.route('/logout')
class Logout(Resource):
    @require_auth()
    @api.response(200, 'Logout successful')
    def post(self):
        """Logout current user."""
        token = request.headers.get('Authorization')
        if token and token.startswith('Bearer '):
            token = token[7:]
            
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM sessions WHERE token = ?', (token,))
        conn.commit()
        conn.close()
        
        return {'message': 'Logout successful'}, 200

# ============================================================================
# User Management Endpoints (Admin only)
# ============================================================================

@users_ns.route('')
class UserList(Resource):
    @require_auth(['Admin'])
    @api.marshal_list_with(user_model)
    @api.response(200, 'Users retrieved successfully')
    def get(self):
        """Get list of all users (Admin only)."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, is_active, created_at FROM users')
        users = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': u[0],
                'username': u[1],
                'role': u[2],
                'is_active': bool(u[3]),
                'created_at': u[4]
            } for u in users
        ], 200
    
    @require_auth(['Admin'])
    @api.expect(user_create_model)
    @api.response(201, 'User created successfully')
    @api.response(400, 'Invalid input')
    def post(self):
        """Create a new user (Admin only)."""
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')
        
        if not all([username, password, role]):
            abort(400, 'Username, password, and role required')
        
        if role not in ['Planner', 'Commuter']:
            abort(400, 'Role must be Planner or Commuter')
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if username already exists
        cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
        if cursor.fetchone():
            conn.close()
            abort(409, 'Username already exists')
        
        password_hash = generate_password_hash(password)
        cursor.execute('''
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        ''', (username, password_hash, role))
        user_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            'id': user_id,
            'username': username,
            'role': role,
            'is_active': True
        }, 201

@users_ns.route('/<int:user_id>')
class UserDetail(Resource):
    @require_auth(['Admin'])
    @api.marshal_with(user_model)
    @api.response(200, 'User retrieved successfully')
    @api.response(404, 'User not found')
    def get(self, user_id):
        """Get a specific user by ID (Admin only)."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT id, username, role, is_active, created_at FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        if not user:
            abort(404, 'User not found')
        
        return {
            'id': user[0],
            'username': user[1],
            'role': user[2],
            'is_active': bool(user[3]),
            'created_at': user[4]
        }, 200
    
    @require_auth(['Admin'])
    @api.expect(user_update_model)
    @api.response(200, 'User updated successfully')
    @api.response(404, 'User not found')
    def put(self, user_id):
        """Activate or deactivate a user (Admin only)."""
        data = request.json
        is_active = data.get('is_active')
        
        if is_active is None:
            abort(400, 'is_active field required')
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute('SELECT id, role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            abort(404, 'User not found')
        
        # Prevent deactivating admin users
        if user[1] == 'Admin' and not is_active:
            conn.close()
            abort(400, 'Cannot deactivate Admin users')
        
        cursor.execute('''
            UPDATE users SET is_active = ? WHERE id = ?
        ''', (1 if is_active else 0, user_id))
        conn.commit()
        conn.close()
        
        return {'message': f'User {"activated" if is_active else "deactivated"} successfully'}, 200
    
    @require_auth(['Admin'])
    @api.response(204, 'User deleted successfully')
    @api.response(404, 'User not found')
    def delete(self, user_id):
        """Delete a user (Admin only)."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if user exists and is not an admin
        cursor.execute('SELECT role FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            abort(404, 'User not found')
        
        if user[0] == 'Admin':
            conn.close()
            abort(400, 'Cannot delete Admin users')
        
        # Delete user's sessions and favourites first
        cursor.execute('DELETE FROM sessions WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM favourites WHERE user_id = ?', (user_id,))
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        conn.close()
        
        return '', 204

# ============================================================================
# Agency Import Endpoints
# ============================================================================

@agencies_ns.route('/import')
class AgencyImport(Resource):
    @require_auth(['Admin', 'Planner'])
    @api.expect(agency_import_model)
    @api.response(200, 'Agency data imported successfully')
    @api.response(400, 'Invalid agency ID')
    @api.response(403, 'Insufficient permissions')
    def post(self):
        """Import bus agency data from GTFS API (Admin and Planner only)."""
        data = request.json
        agency_id = data.get('agency_id')
        
        if not agency_id:
            abort(400, 'Agency ID required')
        
        # Validate agency ID
        if not (agency_id.startswith('GSBC') or agency_id.startswith('SBSC')):
            abort(400, 'Invalid agency ID. Only GSBC and SBSC prefixed agencies are allowed')
        
        # Download GTFS data
        headers = {'Authorization': f'apikey {TRANSPORT_API_KEY}'}
        url = f'{TRANSPORT_API_BASE_URL}/buses/{agency_id}'
        
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            abort(500, f'Failed to fetch GTFS data: {str(e)}')
        
        # Parse and store GTFS data
        try:
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                conn = sqlite3.connect(DB_FILE)
                cursor = conn.cursor()
                
                # Clear existing data for this agency
                cursor.execute('DELETE FROM shapes WHERE shape_id IN (SELECT shape_id FROM trips WHERE route_id IN (SELECT route_id FROM routes WHERE agency_id = ?))', (agency_id,))
                cursor.execute('DELETE FROM stop_times WHERE trip_id IN (SELECT trip_id FROM trips WHERE route_id IN (SELECT route_id FROM routes WHERE agency_id = ?))', (agency_id,))
                cursor.execute('DELETE FROM trips WHERE route_id IN (SELECT route_id FROM routes WHERE agency_id = ?)', (agency_id,))
                cursor.execute('DELETE FROM routes WHERE agency_id = ?', (agency_id,))
                cursor.execute('DELETE FROM agencies WHERE agency_id = ?', (agency_id,))
                
                # Process agency.txt
                if 'agency.txt' in zip_file.namelist():
                    with zip_file.open('agency.txt') as f:
                        df = pd.read_csv(io.TextIOWrapper(f, 'utf-8'))
                        for _, row in df.iterrows():
                            cursor.execute('''
                                INSERT OR REPLACE INTO agencies 
                                (agency_id, agency_name, agency_url, agency_timezone, agency_lang, agency_phone)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (
                                agency_id,  # Use provided agency_id
                                row.get('agency_name', ''),
                                row.get('agency_url', ''),
                                row.get('agency_timezone', ''),
                                row.get('agency_lang', ''),
                                row.get('agency_phone', '')
                            ))
                
                # Process routes.txt
                if 'routes.txt' in zip_file.namelist():
                    with zip_file.open('routes.txt') as f:
                        df = pd.read_csv(io.TextIOWrapper(f, 'utf-8'))
                        for _, row in df.iterrows():
                            cursor.execute('''
                                INSERT OR REPLACE INTO routes 
                                (route_id, agency_id, route_short_name, route_long_name, 
                                 route_desc, route_type, route_url, route_color, route_text_color)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                str(row.get('route_id', '')),
                                agency_id,  # Use provided agency_id
                                row.get('route_short_name', ''),
                                row.get('route_long_name', ''),
                                row.get('route_desc', ''),
                                row.get('route_type', 0),
                                row.get('route_url', ''),
                                row.get('route_color', ''),
                                row.get('route_text_color', '')
                            ))
                
                # Process stops.txt
                if 'stops.txt' in zip_file.namelist():
                    with zip_file.open('stops.txt') as f:
                        df = pd.read_csv(io.TextIOWrapper(f, 'utf-8'))
                        for _, row in df.iterrows():
                            cursor.execute('''
                                INSERT OR REPLACE INTO stops 
                                (stop_id, stop_code, stop_name, stop_desc, stop_lat, stop_lon,
                                 zone_id, stop_url, location_type, parent_station, 
                                 stop_timezone, wheelchair_boarding)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                str(row.get('stop_id', '')),
                                row.get('stop_code', ''),
                                row.get('stop_name', ''),
                                row.get('stop_desc', ''),
                                row.get('stop_lat', 0),
                                row.get('stop_lon', 0),
                                row.get('zone_id', ''),
                                row.get('stop_url', ''),
                                row.get('location_type', 0),
                                row.get('parent_station', ''),
                                row.get('stop_timezone', ''),
                                row.get('wheelchair_boarding', 0)
                            ))
                
                # Process trips.txt
                if 'trips.txt' in zip_file.namelist():
                    with zip_file.open('trips.txt') as f:
                        df = pd.read_csv(io.TextIOWrapper(f, 'utf-8'))
                        for _, row in df.iterrows():
                            cursor.execute('''
                                INSERT OR REPLACE INTO trips 
                                (trip_id, route_id, service_id, trip_headsign, trip_short_name,
                                 direction_id, block_id, shape_id, wheelchair_accessible, bikes_allowed)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                str(row.get('trip_id', '')),
                                str(row.get('route_id', '')),
                                str(row.get('service_id', '')),
                                row.get('trip_headsign', ''),
                                row.get('trip_short_name', ''),
                                row.get('direction_id', 0),
                                row.get('block_id', ''),
                                str(row.get('shape_id', '')),
                                row.get('wheelchair_accessible', 0),
                                row.get('bikes_allowed', 0)
                            ))
                
                # Process stop_times.txt
                if 'stop_times.txt' in zip_file.namelist():
                    with zip_file.open('stop_times.txt') as f:
                        df = pd.read_csv(io.TextIOWrapper(f, 'utf-8'))
                        for _, row in df.iterrows():
                            cursor.execute('''
                                INSERT OR REPLACE INTO stop_times 
                                (trip_id, arrival_time, departure_time, stop_id, stop_sequence,
                                 stop_headsign, pickup_type, drop_off_type, shape_dist_traveled)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                str(row.get('trip_id', '')),
                                row.get('arrival_time', ''),
                                row.get('departure_time', ''),
                                str(row.get('stop_id', '')),
                                row.get('stop_sequence', 0),
                                row.get('stop_headsign', ''),
                                row.get('pickup_type', 0),
                                row.get('drop_off_type', 0),
                                row.get('shape_dist_traveled', 0)
                            ))
                
                # Process shapes.txt
                if 'shapes.txt' in zip_file.namelist():
                    with zip_file.open('shapes.txt') as f:
                        df = pd.read_csv(io.TextIOWrapper(f, 'utf-8'))
                        for _, row in df.iterrows():
                            cursor.execute('''
                                INSERT OR REPLACE INTO shapes 
                                (shape_id, shape_pt_lat, shape_pt_lon, shape_pt_sequence, shape_dist_traveled)
                                VALUES (?, ?, ?, ?, ?)
                            ''', (
                                str(row.get('shape_id', '')),
                                row.get('shape_pt_lat', 0),
                                row.get('shape_pt_lon', 0),
                                row.get('shape_pt_sequence', 0),
                                row.get('shape_dist_traveled', 0)
                            ))
                
                conn.commit()
                conn.close()
                
        except Exception as e:
            abort(500, f'Failed to process GTFS data: {str(e)}')
        
        return {'message': f'Agency {agency_id} data imported successfully'}, 200

@agencies_ns.route('')
class AgencyList(Resource):
    @require_auth()
    @api.response(200, 'Agencies retrieved successfully')
    def get(self):
        """Get list of imported agencies."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM agencies')
        agencies = cursor.fetchall()
        conn.close()
        
        return [
            {
                'agency_id': a[0],
                'agency_name': a[1],
                'agency_url': a[2],
                'agency_timezone': a[3],
                'imported_at': a[6]
            } for a in agencies
        ], 200

# ============================================================================
# Route Endpoints
# ============================================================================

@routes_ns.route('')
class RouteList(Resource):
    @require_auth()
    @api.expect(pagination_parser)
    @api.response(200, 'Routes retrieved successfully')
    def get(self):
        """Get all routes with pagination."""
        args = pagination_parser.parse_args()
        page = args.get('page', 1)
        per_page = args.get('per_page', 20)
        offset = (page - 1) * per_page
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get total count
        cursor.execute('SELECT COUNT(*) FROM routes')
        total = cursor.fetchone()[0]
        
        # Get paginated results
        cursor.execute('''
            SELECT route_id, agency_id, route_short_name, route_long_name, route_type
            FROM routes
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        routes = cursor.fetchall()
        conn.close()
        
        return {
            'total': total,
            'page': page,
            'per_page': per_page,
            'routes': [
                {
                    'route_id': r[0],
                    'agency_id': r[1],
                    'route_short_name': r[2],
                    'route_long_name': r[3],
                    'route_type': r[4]
                } for r in routes
            ]
        }, 200

@routes_ns.route('/<string:route_id>')
class RouteDetail(Resource):
    @require_auth()
    @api.marshal_with(route_model)
    @api.response(200, 'Route retrieved successfully')
    @api.response(404, 'Route not found')
    def get(self, route_id):
        """Get a specific route by ID."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT route_id, agency_id, route_short_name, route_long_name, route_type
            FROM routes WHERE route_id = ?
        ''', (route_id,))
        route = cursor.fetchone()
        conn.close()
        
        if not route:
            abort(404, 'Route not found')
        
        return {
            'route_id': route[0],
            'agency_id': route[1],
            'route_short_name': route[2],
            'route_long_name': route[3],
            'route_type': str(route[4])
        }, 200

@routes_ns.route('/agency/<string:agency_id>')
class RoutesByAgency(Resource):
    @require_auth()
    @api.expect(pagination_parser)
    @api.response(200, 'Routes retrieved successfully')
    @api.response(404, 'Agency not found')
    def get(self, agency_id):
        """Get all routes for a specific agency."""
        args = pagination_parser.parse_args()
        page = args.get('page', 1)
        per_page = args.get('per_page', 20)
        offset = (page - 1) * per_page
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if agency exists
        cursor.execute('SELECT agency_id FROM agencies WHERE agency_id = ?', (agency_id,))
        if not cursor.fetchone():
            conn.close()
            abort(404, 'Agency not found')
        
        # Get total count
        cursor.execute('SELECT COUNT(*) FROM routes WHERE agency_id = ?', (agency_id,))
        total = cursor.fetchone()[0]
        
        # Get paginated results
        cursor.execute('''
            SELECT route_id, agency_id, route_short_name, route_long_name, route_type
            FROM routes WHERE agency_id = ?
            LIMIT ? OFFSET ?
        ''', (agency_id, per_page, offset))
        routes = cursor.fetchall()
        conn.close()
        
        return {
            'total': total,
            'page': page,
            'per_page': per_page,
            'agency_id': agency_id,
            'routes': [
                {
                    'route_id': r[0],
                    'agency_id': r[1],
                    'route_short_name': r[2],
                    'route_long_name': r[3],
                    'route_type': r[4]
                } for r in routes
            ]
        }, 200

# ============================================================================
# Trip Endpoints
# ============================================================================

@trips_ns.route('')
class TripList(Resource):
    @require_auth()
    @api.expect(pagination_parser)
    @api.response(200, 'Trips retrieved successfully')
    def get(self):
        """Get all trips with pagination."""
        args = pagination_parser.parse_args()
        page = args.get('page', 1)
        per_page = args.get('per_page', 20)
        offset = (page - 1) * per_page
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM trips')
        total = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT trip_id, route_id, service_id, trip_headsign, direction_id, shape_id
            FROM trips
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        trips = cursor.fetchall()
        conn.close()
        
        return {
            'total': total,
            'page': page,
            'per_page': per_page,
            'trips': [
                {
                    'trip_id': t[0],
                    'route_id': t[1],
                    'service_id': t[2],
                    'trip_headsign': t[3],
                    'direction_id': t[4],
                    'shape_id': t[5]
                } for t in trips
            ]
        }, 200

@trips_ns.route('/<string:trip_id>')
class TripDetail(Resource):
    @require_auth()
    @api.marshal_with(trip_model)
    @api.response(200, 'Trip retrieved successfully')
    @api.response(404, 'Trip not found')
    def get(self, trip_id):
        """Get a specific trip by ID."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT trip_id, route_id, service_id, trip_headsign, direction_id, shape_id
            FROM trips WHERE trip_id = ?
        ''', (trip_id,))
        trip = cursor.fetchone()
        conn.close()
        
        if not trip:
            abort(404, 'Trip not found')
        
        return {
            'trip_id': trip[0],
            'route_id': trip[1],
            'service_id': trip[2],
            'trip_headsign': trip[3],
            'direction_id': trip[4],
            'shape_id': trip[5]
        }, 200

@trips_ns.route('/route/<string:route_id>')
class TripsByRoute(Resource):
    @require_auth()
    @api.expect(pagination_parser)
    @api.response(200, 'Trips retrieved successfully')
    @api.response(404, 'Route not found')
    def get(self, route_id):
        """Get all trips for a specific route."""
        args = pagination_parser.parse_args()
        page = args.get('page', 1)
        per_page = args.get('per_page', 20)
        offset = (page - 1) * per_page
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if route exists
        cursor.execute('SELECT route_id FROM routes WHERE route_id = ?', (route_id,))
        if not cursor.fetchone():
            conn.close()
            abort(404, 'Route not found')
        
        cursor.execute('SELECT COUNT(*) FROM trips WHERE route_id = ?', (route_id,))
        total = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT trip_id, route_id, service_id, trip_headsign, direction_id, shape_id
            FROM trips WHERE route_id = ?
            LIMIT ? OFFSET ?
        ''', (route_id, per_page, offset))
        trips = cursor.fetchall()
        conn.close()
        
        return {
            'total': total,
            'page': page,
            'per_page': per_page,
            'route_id': route_id,
            'trips': [
                {
                    'trip_id': t[0],
                    'route_id': t[1],
                    'service_id': t[2],
                    'trip_headsign': t[3],
                    'direction_id': t[4],
                    'shape_id': t[5]
                } for t in trips
            ]
        }, 200

# ============================================================================
# Stop Endpoints
# ============================================================================

@stops_ns.route('')
class StopList(Resource):
    @require_auth()
    @api.expect(pagination_parser)
    @api.response(200, 'Stops retrieved successfully')
    def get(self):
        """Get all stops with pagination."""
        args = pagination_parser.parse_args()
        page = args.get('page', 1)
        per_page = args.get('per_page', 20)
        offset = (page - 1) * per_page
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM stops')
        total = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT stop_id, stop_name, stop_lat, stop_lon, zone_id, stop_url
            FROM stops
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        stops = cursor.fetchall()
        conn.close()
        
        return {
            'total': total,
            'page': page,
            'per_page': per_page,
            'stops': [
                {
                    'stop_id': s[0],
                    'stop_name': s[1],
                    'stop_lat': s[2],
                    'stop_lon': s[3],
                    'zone_id': s[4],
                    'stop_url': s[5]
                } for s in stops
            ]
        }, 200

@stops_ns.route('/<string:stop_id>')
class StopDetail(Resource):
    @require_auth()
    @api.marshal_with(stop_model)
    @api.response(200, 'Stop retrieved successfully')
    @api.response(404, 'Stop not found')
    def get(self, stop_id):
        """Get a specific stop by ID."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT stop_id, stop_name, stop_lat, stop_lon, zone_id, stop_url
            FROM stops WHERE stop_id = ?
        ''', (stop_id,))
        stop = cursor.fetchone()
        conn.close()
        
        if not stop:
            abort(404, 'Stop not found')
        
        return {
            'stop_id': stop[0],
            'stop_name': stop[1],
            'stop_lat': stop[2],
            'stop_lon': stop[3],
            'zone_id': stop[4],
            'stop_url': stop[5]
        }, 200

@stops_ns.route('/trip/<string:trip_id>')
class StopsByTrip(Resource):
    @require_auth()
    @api.response(200, 'Stops retrieved successfully')
    @api.response(404, 'Trip not found')
    def get(self, trip_id):
        """Get all stops for a specific trip."""
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if trip exists
        cursor.execute('SELECT trip_id FROM trips WHERE trip_id = ?', (trip_id,))
        if not cursor.fetchone():
            conn.close()
            abort(404, 'Trip not found')
        
        cursor.execute('''
            SELECT s.stop_id, s.stop_name, s.stop_lat, s.stop_lon, 
                   st.stop_sequence, st.arrival_time, st.departure_time
            FROM stops s
            JOIN stop_times st ON s.stop_id = st.stop_id
            WHERE st.trip_id = ?
            ORDER BY st.stop_sequence
        ''', (trip_id,))
        stops = cursor.fetchall()
        conn.close()
        
        return {
            'trip_id': trip_id,
            'stops': [
                {
                    'stop_id': s[0],
                    'stop_name': s[1],
                    'stop_lat': s[2],
                    'stop_lon': s[3],
                    'stop_sequence': s[4],
                    'arrival_time': s[5],
                    'departure_time': s[6]
                } for s in stops
            ]
        }, 200

@stops_ns.route('/search')
class StopSearch(Resource):
    @require_auth()
    @api.expect(stop_search_model)
    @api.response(200, 'Search results retrieved successfully')
    def post(self):
        """Search stops by name using fuzzy matching."""
        data = request.json
        query = data.get('query', '').strip()
        
        if not query:
            abort(400, 'Search query required')
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get all stops
        cursor.execute('SELECT stop_id, stop_name FROM stops')
        all_stops = cursor.fetchall()
        
        # Perform fuzzy matching
        stop_names = [(s[0], s[1]) for s in all_stops]
        matches = process.extract(query, [s[1] for s in stop_names], scorer=fuzz.partial_ratio, limit=10)
        
        results = []
        for match_name, score, _ in matches:
            if score > 50:  # Threshold for relevance
                for stop_id, stop_name in stop_names:
                    if stop_name == match_name:
                        # Get associated routes and trips
                        cursor.execute('''
                            SELECT DISTINCT r.route_id, r.route_short_name, r.route_long_name
                            FROM routes r
                            JOIN trips t ON r.route_id = t.route_id
                            JOIN stop_times st ON t.trip_id = st.trip_id
                            WHERE st.stop_id = ?
                        ''', (stop_id,))
                        routes = cursor.fetchall()
                        
                        cursor.execute('''
                            SELECT DISTINCT t.trip_id, t.trip_headsign
                            FROM trips t
                            JOIN stop_times st ON t.trip_id = st.trip_id
                            WHERE st.stop_id = ?
                            LIMIT 5
                        ''', (stop_id,))
                        trips = cursor.fetchall()
                        
                        results.append({
                            'stop_id': stop_id,
                            'stop_name': stop_name,
                            'match_score': score,
                            'routes': [
                                {
                                    'route_id': r[0],
                                    'route_short_name': r[1],
                                    'route_long_name': r[2]
                                } for r in routes
                            ],
                            'sample_trips': [
                                {
                                    'trip_id': t[0],
                                    'trip_headsign': t[1]
                                } for t in trips
                            ]
                        })
                        break
        
        conn.close()
        return {'query': query, 'results': results}, 200

# ============================================================================
# Favourite Routes Endpoints
# ============================================================================

@favourites_ns.route('')
class FavouriteList(Resource):
    @require_auth()
    @api.marshal_list_with(favourite_model)
    @api.response(200, 'Favourites retrieved successfully')
    def get(self):
        """Get current user's favourite routes."""
        user = request.current_user
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT f.id, f.user_id, f.route_id, f.created_at,
                   r.route_short_name, r.route_long_name
            FROM favourites f
            LEFT JOIN routes r ON f.route_id = r.route_id
            WHERE f.user_id = ?
        ''', (user['id'],))
        favourites = cursor.fetchall()
        conn.close()
        
        return [
            {
                'id': f[0],
                'user_id': f[1],
                'route_id': f[2],
                'created_at': f[3]
            } for f in favourites
        ], 200
    
    @require_auth()
    @api.expect(favourite_create_model)
    @api.response(201, 'Favourite added successfully')
    @api.response(400, 'Invalid input or limit exceeded')
    def post(self):
        """Add a route to favourites (max 2 per user)."""
        user = request.current_user
        data = request.json
        route_id = data.get('route_id')
        
        if not route_id:
            abort(400, 'Route ID required')
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if route exists
        cursor.execute('SELECT route_id FROM routes WHERE route_id = ?', (route_id,))
        if not cursor.fetchone():
            conn.close()
            abort(404, 'Route not found')
        
        # Check current favourite count
        cursor.execute('SELECT COUNT(*) FROM favourites WHERE user_id = ?', (user['id'],))
        count = cursor.fetchone()[0]
        if count >= 2:
            conn.close()
            abort(400, 'Maximum of 2 favourite routes allowed')
        
        # Check if already favourited
        cursor.execute('SELECT id FROM favourites WHERE user_id = ? AND route_id = ?', 
                      (user['id'], route_id))
        if cursor.fetchone():
            conn.close()
            abort(409, 'Route already in favourites')
        
        # Add favourite
        cursor.execute('''
            INSERT INTO favourites (user_id, route_id)
            VALUES (?, ?)
        ''', (user['id'], route_id))
        favourite_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return {
            'id': favourite_id,
            'user_id': user['id'],
            'route_id': route_id
        }, 201

@favourites_ns.route('/<int:favourite_id>')
class FavouriteDetail(Resource):
    @require_auth()
    @api.response(204, 'Favourite deleted successfully')
    @api.response(404, 'Favourite not found')
    def delete(self, favourite_id):
        """Remove a route from favourites."""
        user = request.current_user
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Check if favourite exists and belongs to user
        cursor.execute('SELECT id FROM favourites WHERE id = ? AND user_id = ?', 
                      (favourite_id, user['id']))
        if not cursor.fetchone():
            conn.close()
            abort(404, 'Favourite not found')
        
        cursor.execute('DELETE FROM favourites WHERE id = ?', (favourite_id,))
        conn.commit()
        conn.close()
        
        return '', 204

# ============================================================================
# Visualisation and Export Endpoints
# ============================================================================

@visualisation_ns.route('/favourites/map')
class FavouriteRoutesMap(Resource):
    @require_auth()
    @api.response(200, 'Map generated successfully')
    @api.response(404, 'No favourite routes found')
    def get(self):
        """Generate a map showing favourite routes."""
        user = request.current_user
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get favourite routes
        cursor.execute('''
            SELECT f.route_id, r.route_short_name, r.route_long_name
            FROM favourites f
            JOIN routes r ON f.route_id = r.route_id
            WHERE f.user_id = ?
        ''', (user['id'],))
        favourites = cursor.fetchall()
        
        if not favourites:
            conn.close()
            abort(404, 'No favourite routes found')
        
        # Create map plot
        fig, ax = plt.subplots(figsize=(12, 8))
        colors = ['blue', 'red']  # Different colors for each route
        
        for idx, (route_id, short_name, long_name) in enumerate(favourites):
            # Get shape points for the route
            cursor.execute('''
                SELECT DISTINCT s.shape_pt_lat, s.shape_pt_lon
                FROM shapes s
                JOIN trips t ON s.shape_id = t.shape_id
                WHERE t.route_id = ?
                ORDER BY s.shape_pt_sequence
                LIMIT 1000
            ''', (route_id,))
            shape_points = cursor.fetchall()
            
            if shape_points:
                lats = [p[0] for p in shape_points]
                lons = [p[1] for p in shape_points]
                ax.plot(lons, lats, color=colors[idx % 2], 
                       label=f'{short_name} - {long_name}', linewidth=2, alpha=0.7)
                
                # Add route info as text
                if lons and lats:
                    ax.text(lons[0], lats[0], short_name, fontsize=10, fontweight='bold')
        
        ax.set_xlabel('Longitude')
        ax.set_ylabel('Latitude')
        ax.set_title(f'Favourite Routes Map for {user["username"]}')
        ax.legend()
        ax.grid(True, alpha=0.3)
        
        # Save to bytes buffer
        buf = io.BytesIO()
        plt.savefig(buf, format='png', dpi=100, bbox_inches='tight')
        buf.seek(0)
        plt.close()
        
        conn.close()
        
        return send_file(buf, mimetype='image/png', as_attachment=False)

@visualisation_ns.route('/favourites/export')
class FavouriteRoutesExport(Resource):
    @require_auth()
    @api.response(200, 'CSV file generated successfully')
    @api.response(404, 'No favourite routes found')
    def get(self):
        """Export favourite routes data as CSV."""
        user = request.current_user
        
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        # Get favourite routes with details
        cursor.execute('''
            SELECT r.route_id, r.route_short_name, r.route_long_name, 
                   r.route_type, a.agency_name, COUNT(DISTINCT t.trip_id) as trip_count,
                   COUNT(DISTINCT st.stop_id) as stop_count
            FROM favourites f
            JOIN routes r ON f.route_id = r.route_id
            LEFT JOIN agencies a ON r.agency_id = a.agency_id
            LEFT JOIN trips t ON r.route_id = t.route_id
            LEFT JOIN stop_times st ON t.trip_id = st.trip_id
            WHERE f.user_id = ?
            GROUP BY r.route_id
        ''', (user['id'],))
        
        data = cursor.fetchall()
        conn.close()
        
        if not data:
            abort(404, 'No favourite routes found')
        
        # Create CSV
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Route ID', 'Short Name', 'Long Name', 'Route Type', 
                        'Agency Name', 'Trip Count', 'Stop Count'])
        writer.writerows(data)
        
        # Convert to bytes
        output.seek(0)
        bytes_output = io.BytesIO()
        bytes_output.write(output.getvalue().encode('utf-8'))
        bytes_output.seek(0)
        
        return send_file(
            bytes_output,
            mimetype='text/csv',
            as_attachment=True,
            download_name=f'favourite_routes_{user["username"]}.csv'
        )

# ============================================================================
# Error handlers
# ============================================================================

@app.errorhandler(401)
def unauthorized(e):
    return {'message': 'Authentication required'}, 401

@app.errorhandler(403)
def forbidden(e):
    return {'message': 'Insufficient permissions'}, 403

@app.errorhandler(404)
def not_found(e):
    return {'message': 'Resource not found'}, 404

@app.errorhandler(500)
def internal_error(e):
    return {'message': 'Internal server error'}, 500

# ============================================================================
# Main execution
# ============================================================================

if __name__ == '__main__':
    import sys
    import socket
    
    # Initialize database
    init_database()
    
    # Function to check if port is available
    def is_port_available(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('127.0.0.1', port))
        sock.close()
        return result != 0
    
    # Get port from command line or find available port
    port = 5000
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"Invalid port number: {sys.argv[1]}, using default port 5000")
    
    # Find available port if specified port is in use
    if not is_port_available(port):
        print(f"Port {port} is already in use!")
        print("Searching for available port...")
        
        # Try alternative ports
        alternative_ports = [5001, 5002, 8000, 8080, 3000, 3001, 4000]
        port_found = False
        
        for alt_port in alternative_ports:
            if is_port_available(alt_port):
                port = alt_port
                port_found = True
                print(f"Using port {port} instead")
                break
        
        if not port_found:
            print("ERROR: No available ports found!")
            print("Please specify a port: python3 z5540213_api.py <port>")
            sys.exit(1)
    
    print(f"\n{'='*60}")
    print(f"Starting API server on http://localhost:{port}")
    print(f"Swagger UI available at http://localhost:{port}/swagger")
    print(f"{'='*60}\n")
    
    # Run the Flask app WITHOUT debug mode to avoid reload issues
    app.run(host='0.0.0.0', port=port, debug=False)
