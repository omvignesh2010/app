from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt

app = Flask(__name__)
CORS(app)

client = MongoClient("mongodb+srv://project:project@project.yxrqd7p.mongodb.net/")  
db = client["project_db"]
collection = db["sign_up"]

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('fullName')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({"message": "Missing fields"}), 400

    # Check if user already exists
    if collection.find_one({"email": email}):
        return jsonify({"message": "User already exists"}), 409

    # Hash the password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    collection.insert_one({
        "name": name,
        "email": email,
        "password": hashed_password.decode('utf-8')
    })

    return jsonify({"message": "User registered successfully!"}), 201

if __name__ == '__main__':
    app.run(debug=True)
