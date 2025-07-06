from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt
import re

app = Flask(__name__)
CORS(app)

client = MongoClient("mongodb+srv://project:project@project.yxrqd7p.mongodb.net/?retryWrites=true&w=majority&appName=Project")
db = client["project_db"]
collection = db["sign_up"]

# Password strength check
def is_strong_password(password):
    return bool(re.match(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", password))

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('fullName')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({"message": "Missing fields"}), 400

    if not is_strong_password(password):
        return jsonify({"message": "Weak password"}), 400

    if collection.find_one({"email": email}):
        return jsonify({"message": "User already exists"}), 409

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    collection.insert_one({
        "name": name,
        "email": email,
        "password": hashed_password.decode('utf-8')
    })

    return jsonify({"message": "User registered successfully!"}), 201

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
