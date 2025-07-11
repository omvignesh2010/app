from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
import bcrypt
import traceback

app = Flask(__name__)
CORS(app)

client = MongoClient("mongodb+srv://project:project@project.yxrqd7p.mongodb.net/?retryWrites=true&w=majority&appName=Project")
db = client["project_db"]
collection = db["sign_up"]

@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        print("Login request received:", data)

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"message": "Missing email or password"}), 400

        user = collection.find_one({"email": email})
        if not user:
            return jsonify({"message": "User not found"}), 404

        db_password = user.get("password")
        if not db_password:
            return jsonify({"message": "Password not found in DB"}), 500

        if bcrypt.checkpw(password.encode('utf-8'), db_password.encode('utf-8')):
            return jsonify({"message": "Login success", "user": user["name"]}), 200
        else:
            return jsonify({"message": "Invalid credentials"}), 401

    except Exception as e:
        print("Login error:", e)
        traceback.print_exc()
        return jsonify({"message": "Internal server error"}), 500

@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()
        print("Signup request received:", data)

        name = data.get('fullName')
        email = data.get('email')
        password = data.get('password')

        if not name or not email or not password:
            return jsonify({"message": "Missing fields"}), 400

        if collection.find_one({"email": email}):
            return jsonify({"message": "User already exists"}), 409

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        collection.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password.decode('utf-8')
        })

        return jsonify({"message": "User registered successfully!"}), 201

    except Exception as e:
        print("Signup error:", e)
        traceback.print_exc()
        return jsonify({"message": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=True)