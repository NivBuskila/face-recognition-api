from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
import os
from flasgger import Swagger
import jwt
from functools import wraps
from azure.cognitiveservices.vision.face import FaceClient
from msrest.authentication import CognitiveServicesCredentials
import base64
import io

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Add JWT Secret Key
app.config['SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-secret-key-here')

# Azure Face Client
face_client = FaceClient(
    os.getenv('AZURE_ENDPOINT'),
    CognitiveServicesCredentials(os.getenv('AZURE_KEY'))
)

# Swagger configuration
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/docs"
}

swagger = Swagger(app, config=swagger_config)

# MongoDB connection
MONGO_URI = os.getenv('MONGO_URI')
client = MongoClient(MONGO_URI)
db = client['face_recognition_db']
users_collection = db['users']

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]
            
        if not token:
            return jsonify({
                'error': 'Authentication token is missing'
            }), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({
                'error': 'Invalid token'
            }), 401
            
        return f(*args, **kwargs)
    
    return decorated

@app.route('/health', methods=['GET'])
def health_check():
    """Health Check Endpoint
    ---
    responses:
      200:
        description: Service is healthy
    """
    return jsonify({
        "status": "healthy",
        "message": "Service is running"
    }), 200

@app.route('/api/users', methods=['POST'])
def register_user():
    try:
        app.logger.info("Received registration request")
        data = request.get_json()
        app.logger.info(f"Request data: {data.keys()}")
        
        if not data or 'userId' not in data or 'faceData' not in data:
            app.logger.error("Missing required fields")
            return jsonify({
                "error": "Missing required fields"
            }), 400
            
        app.logger.info(f"Processing image for user: {data['userId']}")
        app.logger.info(f"Image data length: {len(data['faceData'])}")
        
        # Add padding if needed
        faceData = data['faceData']
        padding = len(faceData) % 4
        if padding:
            faceData += '=' * (4 - padding)
            
        try:
            # Verify face in image
            image_data = base64.b64decode(faceData)
            detected_faces = face_client.face.detect_with_stream(io.BytesIO(image_data))
            
            if not detected_faces:
                return jsonify({
                    "error": "No face detected in image"
                }), 400
                
            # Store user data
            new_user = {
                "userId": data['userId'],
                "faceData": faceData,  # שמור את הstring המתוקן
                "faceId": str(detected_faces[0].face_id),
                "createdAt": datetime.utcnow(),
                "status": "active"
            }
            
            result = users_collection.insert_one(new_user)
            
            return jsonify({
                "message": "User registered successfully",
                "userId": data['userId'],
                "_id": str(result.inserted_id)
            }), 201
            
        except Exception as e:
            return jsonify({
                "error": f"Error processing image: {str(e)}"
            }), 400
            
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    """Update User
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
          required:
            - faceData
          properties:
            faceData:
              type: string
    responses:
      200:
        description: User updated successfully
      404:
        description: User not found
    """
    try:
        data = request.get_json()
        
        if not data or 'faceData' not in data:
            return jsonify({
                "error": "Missing face data"
            }), 400
            
        # Verify face in new image
        image_data = base64.b64decode(data['faceData'])
        detected_faces = face_client.face.detect_with_stream(io.BytesIO(image_data))
        
        if not detected_faces:
            return jsonify({
                "error": "No face detected in image"
            }), 400
            
        result = users_collection.update_one(
            {"userId": user_id},
            {
                "$set": {
                    "faceData": data['faceData'],
                    "faceId": str(detected_faces[0].face_id),
                    "updatedAt": datetime.utcnow()
                }
            }
        )
        
        if result.matched_count == 0:
            return jsonify({
                "error": "User not found"
            }), 404
            
        return jsonify({
            "message": "User updated successfully",
            "userId": user_id
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

@app.route('/api/users/<user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    """Delete User
    ---
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
        result = users_collection.delete_one({"userId": user_id})
        
        if result.deleted_count == 0:
            return jsonify({
                "error": "User not found"
            }), 404
            
        return jsonify({
            "message": "User deleted successfully",
            "userId": user_id
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

@app.route('/api/users/<user_id>/verify', methods=['POST'])
def verify_user(user_id):
    """Verify User
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
          required:
            - faceData
          properties:
            faceData:
              type: string
    responses:
      200:
        description: Verification successful
      404:
        description: User not found
    """
    try:
        data = request.get_json()
        
        if not data or 'faceData' not in data:
            return jsonify({
                "error": "Missing face data"
            }), 400
            
        user = users_collection.find_one({"userId": user_id})
        if not user:
            return jsonify({
                "error": "User not found"
            }), 404
            
        # Detect faces in both images
        stored_image = base64.b64decode(user['faceData'])
        input_image = base64.b64decode(data['faceData'])
        
        stored_faces = face_client.face.detect_with_stream(io.BytesIO(stored_image))
        input_faces = face_client.face.detect_with_stream(io.BytesIO(input_image))
        
        if not stored_faces or not input_faces:
            return jsonify({
                "error": "No face detected in one or both images"
            }), 400
        
        # Compare faces
        verify_result = face_client.face.verify_face_to_face(
            stored_faces[0].face_id,
            input_faces[0].face_id
        )
        
        return jsonify({
            "success": verify_result.is_identical,
            "userId": user_id,
            "confidence": verify_result.confidence
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

@app.route('/api/faces/compare', methods=['POST'])
def compare_faces():
    """Compare two face images
    ---
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
            faceData2:
              type: string
    responses:
      200:
        description: Comparison successful
      400:
        description: Invalid input
    """
    try:
        data = request.get_json()
        
        if not data or 'faceData1' not in data or 'faceData2' not in data:
            return jsonify({
                "error": "Missing face data"
            }), 400
            
        # Decode both images
        image1_data = base64.b64decode(data['faceData1'])
        image2_data = base64.b64decode(data['faceData2'])
        
        # Detect faces in both images
        faces1 = face_client.face.detect_with_stream(io.BytesIO(image1_data))
        faces2 = face_client.face.detect_with_stream(io.BytesIO(image2_data))
        
        if not faces1 or not faces2:
            return jsonify({
                "error": "No face detected in one or both images"
            }), 400
        
        # Compare faces
        verify_result = face_client.face.verify_face_to_face(
            faces1[0].face_id,
            faces2[0].face_id
        )
        
        return jsonify({
            "success": verify_result.is_identical,
            "confidence": verify_result.confidence
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500
    
@app.route('/api/auth/login', methods=['POST'])
def login():
    """Login to get JWT token
    ---
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - username
            - password
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Login successful
      401:
        description: Invalid credentials
    """
    auth = request.json
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({
            'error': 'Missing credentials'
        }), 401
    
    if auth.get('username') != 'admin' or auth.get('password') != 'admin':
        return jsonify({
            'error': 'Invalid credentials'
        }), 401
    
    token = jwt.encode({
        'user': auth.get('username'),
        'exp': datetime.utcnow().timestamp() + 24 * 60 * 60  # 24 hours
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'token': token
    }), 200

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)