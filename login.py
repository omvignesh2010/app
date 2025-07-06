import bcrypt  

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({"message": "Missing email or password"}), 400

    user = collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Check password
    if bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"message": "Incorrect password"}), 401
