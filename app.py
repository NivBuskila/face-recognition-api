from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import cv2
import numpy as np
from PIL import Image
import io
import base64
import logging
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from flasgger import Swagger
import jwt
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

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

# Swagger template configuration
swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "Face Recognition API",
        "description": "API for face recognition services",
        "version": "1.0.0"
    },
    "consumes": ["application/json"],
    "produces": ["application/json"],
    "securityDefinitions": {
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\""
        }
    }
}

swagger_config = {
    "headers": [],
    "specs": [{
        "endpoint": 'apispec',
        "route": '/apispec.json',
        "rule_filter": lambda rule: True,
        "model_filter": lambda tag: True,
    }],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs"
}

swagger = Swagger(app, template=swagger_template, config=swagger_config)

# MongoDB connection with error handling
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
            current_user = admins_collection.find_one({'username': data['username']})
            if not current_user:
                raise jwt.InvalidTokenError
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
            
        return f(*args, **kwargs)
    
    return decorated

def process_face_image(image_data):
    """Process and extract features from face image using OpenCV"""
    try:
        # Remove data:image/jpeg;base64, if present
        if ',' in image_data:
            image_data = image_data.split(',')[1]
            
        # Convert base64 to image
        image_bytes = base64.b64decode(image_data)
        nparr = np.frombuffer(image_bytes, np.uint8)
        image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        
        if image is None:
            return None, "Failed to decode image"
            
        # Load face cascade classifier
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Detect faces
        faces = face_cascade.detectMultiScale(gray, 1.1, 4)
        
        if len(faces) == 0:
            return None, "No face detected in the image"
            
        if len(faces) > 1:
            return None, "Multiple faces detected in the image"
            
        # Extract the face region
        x, y, w, h = faces[0]
        face = image[y:y+h, x:x+w]
        
        # Resize to standard size
        face = cv2.resize(face, (128, 128))
        
        # Convert to grayscale and flatten
        face_gray = cv2.cvtColor(face, cv2.COLOR_BGR2GRAY)
        features = face_gray.flatten().tolist()
        
        return features, None
        
    except Exception as e:
        logger.error(f"Error processing image: {str(e)}")
        return None, str(e)

def compare_faces(face1_features, face2_features, threshold=0.8):
    """Compare two face features using correlation coefficient"""
    try:
        face1 = np.array(face1_features)
        face2 = np.array(face2_features)
        
        # Calculate correlation coefficient
        correlation = np.corrcoef(face1, face2)[0,1]
        similarity = (correlation + 1) / 2  # Convert from [-1,1] to [0,1] range
        
        return {
            "matched": similarity >= threshold,
            "similarity": float(similarity)
        }
        
    except Exception as e:
        logger.error(f"Error comparing faces: {str(e)}")
        return {
            "matched": False,
            "similarity": 0.0
        }

@app.route('/health', methods=['GET'])
def health_check():
    """Health Check Endpoint
    ---
    responses:
      200:
        description: Service is healthy
      500:
        description: Service is unhealthy
    """
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
    """Register new admin
    ---
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
              example: admin
            password:
              type: string
              example: admin123
    responses:
      201:
        description: Admin registered successfully
      400:
        description: Bad request
      409:
        description: Admin already exists
    """
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
    """Admin login
    ---
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
              example: admin
            password:
              type: string
              example: admin123
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
    """
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


@app.route('/api/users', methods=['POST'])
def register_user():
    """Register new user with face data
    ---
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            userId:
              type: string
              example: user123
            faceData:
              type: string
              description: Base64 encoded image
    responses:
      201:
        description: User registered successfully
      400:
        description: Bad request
      409:
        description: User already exists
    """
    try:
        data = request.get_json()
        
        if not data or 'userId' not in data or 'faceData' not in data:
            return jsonify({'error': 'Missing required fields'}), 400
            
        if users_collection.find_one({'userId': data['userId']}):
            return jsonify({'error': 'User already exists'}), 409
            
        features, error = process_face_image(data['faceData'])
        
        if error:
            return jsonify({'error': f'Face processing failed: {error}'}), 400
            
        new_user = {
            'userId': data['userId'],
            'faceData': data['faceData'],
            'faceFeatures': features,
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


@app.route('/api/faces/compare', methods=['POST'])
def compare_faces_endpoint():
    """Compare two face images
    ---
    tags:
      - Face Recognition
    summary: Compare two facial images and determine if they match
    description: Upload two base64 encoded images and receive a comparison result with confidence score
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - faceData1
            - faceData2
          properties:
            faceData1:
              type: string
              description: Base64 encoded string of first facial image
            faceData2:
              type: string
              description: Base64 encoded string of second facial image
    responses:
      200:
        description: Face comparison completed successfully
        schema:
          type: object
          properties:
            verified:
              type: boolean
              description: Whether the faces match
            confidence:
              type: number
              format: float
              description: Confidence score of the match (0-1)
      400:
        description: Invalid request or face processing failed
        schema:
          type: object
          properties:
            error:
              type: string
      500:
        description: Internal server error
        schema:
          type: object
          properties:
            error:
              type: string
    """
    # Implementation remains the same
    try:
        data = request.get_json()
        
        if not data or 'faceData1' not in data or 'faceData2' not in data:
            return jsonify({'error': 'Missing face data'}), 400
            
        features1, error1 = process_face_image(data['faceData1'])
        if error1:
            return jsonify({'error': f'Error processing first image: {error1}'}), 400
            
        features2, error2 = process_face_image(data['faceData2'])
        if error2:
            return jsonify({'error': f'Error processing second image: {error2}'}), 400
        
        result = compare_faces(features1, features2)
        
        return jsonify({
            'verified': result['matched'],
            'confidence': result['similarity']
        }), 200
        
    except Exception as e:
        logger.error(f"Error in compare_faces: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/<user_id>/verify', methods=['POST'])
def verify_user(user_id):
    """Verify user's face
    ---
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            faceData:
              type: string
              description: Base64 encoded image
    responses:
      200:
        description: Verification result
      404:
        description: User not found
    """
    try:
        data = request.get_json()
        
        if not data or 'faceData' not in data:
            return jsonify({'error': 'Missing face data'}), 400
            
        user = users_collection.find_one({'userId': user_id})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        input_features, error = process_face_image(data['faceData'])
        
        if error:
            return jsonify({'error': f'Face processing failed: {error}'}), 400
            
        result = compare_faces(input_features, user['faceFeatures'])
        
        return jsonify({
            'verified': result['matched'],
            'confidence': result['similarity'],
            'userId': user_id
        }), 200
        
    except Exception as e:
        logger.error(f"Error in verify_user: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
    

@app.route('/api/users/<user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    """Delete user
    ---
    security:
      - Bearer: []
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
    responses:
      200:
        description: User deleted successfully
      404:
        description: User not found
    """
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

@app.after_request
def after_request(response):
    """Enable CORS headers"""
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port)