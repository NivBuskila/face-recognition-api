# Face Recognition API

Simple REST API for face recognition services built with Flask and MongoDB.

## Setup

1. Clone the repository
2. Create virtual environment:
```bash
python -m venv venv
```

3. Activate virtual environment:
- Windows:
```bash
venv\Scripts\activate
```
- Linux/Mac:
```bash
source venv/bin/activate
```

4. Install dependencies:
```bash
pip install -r requirements.txt
```

5. Create `.env` file with your MongoDB connection string:
```
MONGO_URI=your_mongodb_atlas_connection_string
PORT=5000
```

6. Run the server:
```bash
python app.py
```

## API Documentation

Full API documentation is available at `/docs` when the server is running.

### Available Endpoints

- `GET /health` - Health check
- `POST /api/users` - Register new user
- `GET /api/users/<user_id>` - Get user data
- `PUT /api/users/<user_id>` - Update user data
- `DELETE /api/users/<user_id>` - Delete user

## Example Usage

Register new user:
```bash
curl -X POST http://localhost:5000/api/users \
  -H "Content-Type: application/json" \
  -d '{"userId": "user123", "faceData": "base64_encoded_face_data"}'
```

## Technologies Used

- Flask
- MongoDB
- Python 3.8+
- Swagger/Flasgger

## License

MIT License