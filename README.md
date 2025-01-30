# Face Recognition API

A robust and secure REST API service for facial recognition and user management, built with Flask and AWS Rekognition.

## Features

The Face Recognition API provides a comprehensive suite of features for facial recognition and user management:

- Real-time face detection and comparison using AWS Rekognition
- Secure user management with face data storage
- JWT-based authentication for admin access
- MongoDB integration for data persistence
- Swagger documentation for API endpoints
- CORS support for cross-origin requests
- Comprehensive error handling and logging
- Health monitoring endpoint

## Technologies

This project is built using the following technologies:

- **Backend Framework**: Flask (Python)
- **Database**: MongoDB
- **Face Recognition**: AWS Rekognition
- **Authentication**: JWT (JSON Web Tokens)
- **Documentation**: Flasgger (Swagger)
- **API Security**: Flask-CORS

## Prerequisites

Before setting up the project, ensure you have the following:

- Python 3.8 or higher
- MongoDB 4.4 or higher
- AWS Account with Rekognition access
- Environment variables configured (see Configuration section)

## Configuration

Create a `.env` file in the root directory with the following variables:

```plaintext
MONGO_URI=your_mongodb_connection_string
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=your_aws_region
JWT_SECRET_KEY=your_jwt_secret
PORT=5000
```

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd face-recognition-api
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # For Unix
venv\Scripts\activate     # For Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables as described in the Configuration section.

5. Run the application:
```bash
python app.py
```

## API Endpoints

### Authentication Endpoints

- `POST /api/auth/register`: Register a new admin user
- `POST /api/auth/login`: Admin login to obtain JWT token

### User Management Endpoints

- `GET /api/users`: Get all registered users (requires admin authentication)
- `GET /api/users/<user_id>`: Get user details by ID (requires admin authentication)
- `POST /api/users`: Register new user with face data
- `PUT /api/users/<user_id>`: Update user face data (requires admin authentication)
- `DELETE /api/users/<user_id>`: Delete user (requires admin authentication)
- `GET /api/users/<user_id>/image`: Get user's face image (requires admin authentication)

### Face Recognition Endpoints

- `POST /api/faces/compare`: Compare two face images
- `POST /api/users/<user_id>/verify`: Verify user identity using face comparison

### System Endpoints

- `GET /health`: System health check
- `GET /docs`: Swagger API documentation

## Security Features

The API implements several security measures:

- JWT-based authentication for admin access
- Password hashing for admin credentials
- CORS protection with configurable origins
- Input validation and sanitization
- Secure error handling to prevent information leakage

## Error Handling

The API provides detailed error responses in the following format:

```json
{
    "error": "Error message description"
}
```

Common error status codes:
- 400: Bad Request
- 401: Unauthorized
- 404: Not Found
- 409: Conflict
- 500: Internal Server Error

## API Documentation

Interactive API documentation is available at `/docs` when the server is running. The documentation includes:

- Detailed endpoint descriptions
- Request/response schemas
- Authentication requirements
- Example requests and responses
- Error scenarios

## Development

To run the application in development mode:

```bash
export FLASK_ENV=development
export FLASK_APP=app.py
flask run
```

## Deployment

The application is designed to be deployed to any cloud platform that supports Python applications. Recommended platforms include:

- AWS Elastic Beanstalk
- Google Cloud Platform
- Heroku
- Digital Ocean

Ensure all environment variables are properly configured in your deployment environment.

## Logging

The application uses Python's built-in logging module configured to log:

- API request information
- Error messages and stack traces
- AWS Rekognition service interactions
- Database operations

Monitor the application health using the `/health` endpoint.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.