
```markdown
# Face Recognition API

A RESTful API for face recognition and user management, built with **Flask** and **MongoDB**.  
This service uses **AWS Rekognition** for face comparison and verification.

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Setup](#setup)
  - [Environment Variables](#environment-variables)
  - [Installation](#installation)
- [Usage](#usage)
  - [Run the Server](#run-the-server)
  - [API Documentation](#api-documentation)
  - [Authentication & Authorization](#authentication--authorization)
- [Endpoints](#endpoints)
  - [Health Check](#health-check)
  - [User Management](#user-management)
  - [Admin & Auth](#admin--auth)
  - [Face Recognition](#face-recognition)
- [Examples](#examples)
  - [Register a New User](#register-a-new-user)
  - [Verify a User](#verify-a-user)
- [Technologies Used](#technologies-used)
- [Deployment](#deployment)
- [License](#license)

---

## Features
- **User Management**: Create, read, update, and delete user data (including face images).
- **Face Recognition**: Compare faces using AWS Rekognition to verify or match users.
- **JWT-based Admin Authentication**: Secure admin endpoints with JWT tokens.
- **Swagger Integration**: Auto-generated API documentation at `/docs`.

---

## Prerequisites
- **Python 3.8+**  
- [Pip](https://pip.pypa.io/en/stable/) or another package manager for Python  
- An active [MongoDB Atlas](https://www.mongodb.com/atlas) account or other MongoDB instance  
- (Optional, for face comparison) [AWS Credentials](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) for Rekognition  

---

## Setup

### Environment Variables

Create a `.env` file in the project's root directory. At minimum, you need the following variables:

```
# MongoDB connection
MONGO_URI=your_mongodb_atlas_connection_string

# Flask and JWT
JWT_SECRET_KEY=your_jwt_secret_key
PORT=5000

# AWS Rekognition
AWS_REGION=your_aws_region
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
```
> **Note**: If you are **not** using AWS Rekognition, you can omit the AWS credentials, but be sure to remove or mock related code.

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/your-repo/face-recognition-api.git
   cd face-recognition-api
   ```

2. **Create and activate a virtual environment** (recommended):
   ```bash
   python -m venv venv
   # Activate:
   # On Windows:
   venv\Scripts\activate
   # On Linux/Mac:
   source venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up `.env`** as described above.

---

## Usage

### Run the Server
```bash
python app.py
```
The API will be available at `http://localhost:5000` by default (or at the port you specified in the `.env`).

### API Documentation
Once the server is up, you can access the Swagger UI at:
```
http://localhost:5000/docs
```
This provides an interactive interface to test all endpoints and view request/response schemas.

### Authentication & Authorization
- **Admin Registration**: You can create new admins via `POST /api/auth/register`.
- **Admin Login**: Obtain a JWT token via `POST /api/auth/login`. Include this token in the `Authorization: Bearer <token>` header for any **protected endpoints**.

---

## Endpoints

> **Note**: This is a summary. Refer to `/docs` (Swagger) for full details, including request/response schemas.

### Health Check
- `GET /health`  
  - Checks API and database connection status.

### User Management
- `POST /api/users`  
  - Register a new user with face data.
- `GET /api/users` (requires admin token)  
  - Retrieve all users (no face images included).
- `GET /api/users/<user_id>` (requires admin token)  
  - Retrieve a single user’s data.
- `GET /api/users/<user_id>/image` (requires admin token)  
  - Retrieve the stored base64 face image for a user.
- `PUT /api/users/<user_id>` (requires admin token)  
  - Update a user’s face data.
- `DELETE /api/users/<user_id>` (requires admin token)  
  - Delete a user.

### Admin & Auth
- `POST /api/auth/register`  
  - Register a new admin (username + password).
- `POST /api/auth/login`  
  - Login as an admin, returns a JWT token.

### Face Recognition
- `POST /api/faces/compare`  
  - Compare two base64 face images (no token required by default – can be changed).
- `POST /api/users/<user_id>/verify`  
  - Compare the provided face image with a stored user’s face data.

---

## Examples

### Register a New User
```bash
curl -X POST http://localhost:5000/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "userId": "user123", 
    "faceData": "data:image/jpeg;base64,<BASE64_STRING>"
  }'
```
> Make sure `faceData` contains a valid base64 image string.

### Verify a User
```bash
curl -X POST http://localhost:5000/api/users/user123/verify \
  -H "Content-Type: application/json" \
  -d '{
    "faceData": "data:image/jpeg;base64,<ANOTHER_BASE64_STRING>"
  }'
```
If the faces match above a threshold, the response will include `"verified": true`.

---

## Technologies Used
- **Flask** (Python micro web framework)  
- **MongoDB** (via [pymongo](https://pypi.org/project/pymongo/))  
- **AWS Rekognition** (optional, for face comparison)  
- **Swagger/Flasgger** for API documentation  
- **JWT** for admin authentication  
- **Python 3.8+**

---

## Deployment
- If you plan to deploy to a cloud provider (e.g., Vercel, Koyeb, AWS, GCP), ensure your environment variables are set accordingly.
- Consider using a production WSGI server such as **gunicorn**:
  ```bash
  pip install gunicorn
  gunicorn app:app --bind=0.0.0.0:$PORT
  ```
- For Docker-based deployment, you can create a simple `Dockerfile`:
  ```dockerfile
  FROM python:3.9-slim
  WORKDIR /app
  COPY requirements.txt .
  RUN pip install -r requirements.txt
  COPY . .
  CMD ["gunicorn", "app:app", "--bind=0.0.0.0:5000"]
  ```
  Then build and run the image:
  ```bash
  docker build -t face-recognition-api .
  docker run -p 5000:5000 face-recognition-api
  ```

---

## License
[MIT License](LICENSE)  
Feel free to use, modify, and distribute this project under the terms of the MIT license.
```

