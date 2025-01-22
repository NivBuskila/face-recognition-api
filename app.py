from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
import os
from flasgger import Swagger
import cv2
import numpy as np
import base64
from io import BytesIO
from PIL import Image

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Swagger configuration
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,  # all in
            "model_filter": lambda tag: True,  # all in
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

@app.route('/health', methods=['GET'])
def health_check():
    """Health Check Endpoint
    ---
    responses:
      200:
        description: Service is healthy
        schema:
          type: object
          properties:
            status:
              type: string
              example: healthy
            message:
              type: string
              example: Service is running
    """
    return jsonify({
        "status": "healthy",
        "message": "Service is running"
    }), 200

@app.route('/api/users', methods=['POST'])
def register_user():
    """Register New User
    ---
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - userId
            - faceData
          properties:
            userId:
              type: string
              example: user123
            faceData:
              type: string
              example: base64_encoded_face_data
    responses:
      201:
        description: User registered successfully
      400:
        description: Missing required fields
      409:
        description: User already exists
      500:
        description: Internal server error
    """
    try:
        data = request.get_json()
        
        if not data or 'userId' not in data or 'faceData' not in data:
            return jsonify({
                "error": "Missing required fields"
            }), 400
        
        existing_user = users_collection.find_one({"userId": data['userId']})
        if existing_user:
            return jsonify({
                "error": "User already exists"
            }), 409
            
        new_user = {
            "userId": data['userId'],
            "faceData": data['faceData'],
            "createdAt": datetime.utcnow()
        }
        
        result = users_collection.insert_one(new_user)
        
        return jsonify({
            "message": "User registered successfully",
            "userId": data['userId'],
            "_id": str(result.inserted_id)
        }), 201
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

@app.route('/api/users/<user_id>', methods=['GET'])
def get_user(user_id):
    """Get User Data
    ---
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: The ID of the user
    responses:
      200:
        description: User data retrieved successfully
      404:
        description: User not found
      500:
        description: Internal server error
    """
    try:
        user = users_collection.find_one({"userId": user_id})
        if not user:
            return jsonify({
                "error": "User not found"
            }), 404
            
        formatted_user = {
            "_id": str(user['_id']),
            "userId": user['userId'],
            "faceData": user['faceData'],
            "createdAt": user['createdAt'].isoformat()
        }
        
        return jsonify(formatted_user), 200
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
def update_user(user_id):
    """Update User Data
    ---
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: The ID of the user
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
              example: new_base64_encoded_face_data
    responses:
      200:
        description: User updated successfully
      400:
        description: Missing face data
      404:
        description: User not found
      500:
        description: Internal server error
    """
    try:
        data = request.get_json()
        
        if not data or 'faceData' not in data:
            return jsonify({
                "error": "Missing face data"
            }), 400
            
        result = users_collection.update_one(
            {"userId": user_id},
            {
                "$set": {
                    "faceData": data['faceData'],
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

@app.route('/api/users/<user_id>/verify', methods=['POST'])
def verify_user(user_id):
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
            
        # Convert base64 images to OpenCV format
        stored_image = base64_to_image(user['faceData'])
        input_image = base64_to_image(data['faceData'])
        
        # Load face detection model
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        
        # Detect faces in both images
        stored_faces = detect_faces(stored_image, face_cascade)
        input_faces = detect_faces(input_image, face_cascade)
        
        if not stored_faces or not input_faces:
            return jsonify({
                "error": "No face detected in one or both images"
            }), 400
        
        # Compare faces using Histogram Comparison
        confidence = compare_faces(stored_faces[0], input_faces[0])
        success = confidence > 0.6
        
        return jsonify({
            "success": success,
            "userId": user_id,
            "confidence": float(confidence)
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

def base64_to_image(base64_string):
    if 'base64,' in base64_string:
        base64_string = base64_string.split('base64,')[1]
    
    image_data = base64.b64decode(base64_string)
    image = Image.open(BytesIO(image_data))
    
    # Convert to OpenCV format
    return cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)

def detect_faces(image, face_cascade):
    # Convert to grayscale
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    # Detect faces
    faces = face_cascade.detectMultiScale(gray, 1.1, 4)
    
    # Crop face regions
    face_images = []
    for (x, y, w, h) in faces:
        face = image[y:y+h, x:x+w]
        face_images.append(cv2.resize(face, (100, 100)))  # Normalize size
    
    return face_images

def compare_faces(face1, face2):
    # Convert to grayscale
    gray1 = cv2.cvtColor(face1, cv2.COLOR_BGR2GRAY)
    gray2 = cv2.cvtColor(face2, cv2.COLOR_BGR2GRAY)
    
    # Compute histograms
    hist1 = cv2.calcHist([gray1], [0], None, [256], [0, 256])
    hist2 = cv2.calcHist([gray2], [0], None, [256], [0, 256])
    
    # Normalize histograms
    cv2.normalize(hist1, hist1)
    cv2.normalize(hist2, hist2)
    
    # Compare histograms
    return float(cv2.compareHist(hist1, hist2, cv2.HISTCMP_CORREL) + 1) / 2

    
@app.route('/api/users/<user_id>', methods=['DELETE'])
def delete_user(user_id):
    """Delete User
    ---
    parameters:
      - name: user_id
        in: path
        type: string
        required: true
        description: The ID of the user
    responses:
      200:
        description: User deleted successfully
      404:
        description: User not found
      500:
        description: Internal server error
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

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)