from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime
import os
from flasgger import Swagger

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