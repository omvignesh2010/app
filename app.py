from flask import Flask, request, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    return jsonify({"status": "Login success", "user": data.get("username")})

@app.route('/signup', methods=['POST'])
def signup():
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

if __name__ == "__main__":
    app.run()
