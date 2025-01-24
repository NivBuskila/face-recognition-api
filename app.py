from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import boto3
import base64
import logging
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from flasgger import Swagger
import jwt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from botocore.exceptions import ClientError

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Configure CORS
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"]
    }
})

# JWT Configuration
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-here')

# Swagger configuration
swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Face Recognition API",
        "description": "API for face recognition services using AWS Rekognition",
        "version": "1.0.0"
    },
    "consumes": ["application/json"],
    "produces": ["application/json"],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using Bearer scheme"
        }
    }
}

swagger = Swagger(app, template=swagger_template)

# Initialize AWS Rekognition client
rekognition_client = boto3.client('rekognition',
    region_name=os.getenv('AWS_REGION')
)

# MongoDB connection
def get_db():
    try:
        client = MongoClient(os.getenv('MONGO_URI'), 
                           serverSelectionTimeoutMS=5000,
                           connectTimeoutMS=5000,
                           socketTimeoutMS=5000)
        db = client['face_recognition_db']
        client.admin.command('ping')
        logger.info("Successfully connected to MongoDB")
        return db
    except Exception as e:
        logger.error(f"Failed to connect to MongoDB: {str(e)}")
        raise

# Initialize database collections
try:
    db = get_db()
    users_collection = db['users']
    admins_collection = db['admins']
except Exception as e:
    logger.error(f"Database initialization failed: {str(e)}")

def token_required(f):
    """Decorator for JWT token verification"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header:
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Invalid Authorization header format'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            if not admins_collection.find_one({'username': data['username']}):
                raise jwt.InvalidTokenError
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
            
        return f(*args, **kwargs)
    return decorated

def compare_faces_aws(source_image: str, target_image: str) -> dict:
    """Compare two face images using AWS Rekognition"""
    try:
        # Remove base64 prefix if present
        if ',' in source_image:
            source_image = source_image.split(',')[1]
        if ',' in target_image:
            target_image = target_image.split(',')[1]

        # Convert base64 to bytes
        source_bytes = base64.b64decode(source_image)
        target_bytes = base64.b64decode(target_image)

        # Compare faces using AWS Rekognition
        response = rekognition_client.compare_faces(
            SourceImage={'Bytes': source_bytes},
            TargetImage={'Bytes': target_bytes},
            SimilarityThreshold=80
        )

        if not response['FaceMatches']:
            return {"verified": False, "confidence": 0.0}

        match = response['FaceMatches'][0]
        return {
            "verified": True,
            "confidence": float(match['Similarity']) / 100
        }

    except ClientError as e:
        logger.error(f"AWS Rekognition error: {str(e)}")
        raise
    except Exception as e:
        logger.error(f"Error in compare_faces: {str(e)}")
        raise

@app.route('/api/faces/compare', methods=['POST'])
def compare_faces_endpoint():
    """Endpoint for face comparison"""
    try:
        data = request.get_json()
        
        if not data or 'faceData1' not in data or 'faceData2' not in data:
            return jsonify({'error': 'Missing face data'}), 400

        result = compare_faces_aws(data['faceData1'], data['faceData2'])
        return jsonify(result), 200

    except ClientError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Error in compare_faces_endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """Health Check Endpoint"""
    try:
        db.command('ping')
        return jsonify({
            "status": "healthy",
            "message": "Service is running",
            "database": "connected"
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "message": str(e),
            "database": "disconnected"
        }), 500

@app.route('/api/auth/register', methods=['POST'])
def register_admin():
    """Register new admin user"""
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
            
        if admins_collection.find_one({'username': data['username']}):
            return jsonify({'error': 'Admin already exists'}), 409
            
        hashed_password = generate_password_hash(data['password'])
        
        new_admin = {
            'username': data['username'],
            'password': hashed_password,
            'created_at': datetime.utcnow()
        }
        
        admins_collection.insert_one(new_admin)
        
        return jsonify({'message': 'Admin registered successfully'}), 201
        
    except Exception as e:
        logger.error(f"Error in register_admin: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    """Admin login endpoint"""
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Missing credentials'}), 401
            
        admin = admins_collection.find_one({'username': data['username']})
        
        if not admin or not check_password_hash(admin['password'], data['password']):
            return jsonify({'error': 'Invalid credentials'}), 401
            
        token = jwt.encode({
            'username': data['username'],
            'exp': datetime.utcnow() + timedelta(days=1)
        }, app.config['SECRET_KEY'])
        
        return jsonify({'token': token}), 200
        
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Update the Swagger configuration
swagger_config = {
    "headers": [],
    "specs": [{
        "endpoint": 'apispec_1',
        "route": '/apispec_1.json',
        "rule_filter": lambda rule: True,
        "model_filter": lambda tag: True,
    }],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs"
}

# Initialize Swagger with the supported parameters
swagger = Swagger(
    app,
    template=swagger_template,
    config=swagger_config
)

# CORS configuration
@app.after_request
def after_request(response):
    """Configure CORS headers"""
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/api/users', methods=['POST'])
def register_user():
    """Register new user with face data"""
    try:
        data = request.get_json()
        
        if not data or 'userId' not in data or 'faceData' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
            
        if users_collection.find_one({'userId': data['userId']}):
            return jsonify({'error': 'User already exists'}), 409

        # Verify face is detectable before storing
        try:
            face_bytes = base64.b64decode(data['faceData'].split(',')[1])
            rekognition_client.detect_faces(Image={'Bytes': face_bytes})
        except:
            return jsonify({'error': 'No valid face detected in image'}), 400
            
        new_user = {
            'userId': data['userId'],
            'faceData': data['faceData'],
            'created_at': datetime.utcnow()
        }
        
        result = users_collection.insert_one(new_user)
        
        return jsonify({
            'message': 'User registered successfully',
            'userId': data['userId'],
            '_id': str(result.inserted_id)
        }), 201
        
    except Exception as e:
        logger.error(f"Error in register_user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>/verify', methods=['POST'])
def verify_user(user_id):
    """Verify user identity using face comparison"""
    try:
        data = request.get_json()
        
        if not data or 'faceData' not in data:
            return jsonify({'error': 'Missing face data'}), 400
            
        user = users_collection.find_one({'userId': user_id})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        result = compare_faces_aws(user['faceData'], data['faceData'])
        result['userId'] = user_id
        
        return jsonify(result), 200
        
    except Exception as e:
        logger.error(f"Error in verify_user: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    """Delete user record"""
    try:
        result = users_collection.delete_one({'userId': user_id})
        
        if result.deleted_count == 0:
            return jsonify({'error': 'User not found'}), 404
            
        return jsonify({
            'message': 'User deleted successfully',
            'userId': user_id
        }), 200
        
    except Exception as e:
        logger.error(f"Error in delete_user: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)