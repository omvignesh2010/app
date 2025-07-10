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
    data = request.json
    return jsonify({"status": "Signup success", "user": data.get("username")})

if __name__ == "__main__":
    app.run()
