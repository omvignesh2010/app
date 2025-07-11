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
def is_strong_password(password):
    return bool(re.match(r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$", password))
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"message": "Missing email or password"}), 400
    user = collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404
    if bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
        return jsonify({"message": "Login success", "user": user["name"]}), 200
    else:
        return jsonify({"message": "Invalid credentials"}), 401
@app.route('/signup', methods=['POST'])
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
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    collection.insert_one({
        "name": name,
        "email": email,
        "password": hashed_password.decode('utf-8')
    })
    return jsonify({"message": "User registered successfully!"}), 201
if __name__ == "__main__":
    app.run(debug=True)
