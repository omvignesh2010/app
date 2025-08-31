from flask import Flask, request, jsonify
from flask_cors import CORS
import os, certifi, random, requests, traceback
from pymongo import MongoClient
import bcrypt
from datetime import datetime, timedelta
app = Flask(__name__)
CORS(app)
client = MongoClient(
    "mongodb+srv://project:project@project.yxrqd7p.mongodb.net/?retryWrites=true&w=majority&appName=Project",
    tlsCAFile=certifi.where()
)
db = client["project_db"]
collection = db["sign_up"]
otp_collection = db["password_otps"]
try:
    otp_collection.create_index("expiresAt", expireAfterSeconds=0)
except Exception as _e:
    print("TTL index creation warning:", _e)
BREVO_API_KEY = "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"
SENDER_EMAIL = "oomvignesh@gmail.com"
SENDER_NAME  = "VITA GO"
BREVO_URL = "https://api.brevo.com/v3/smtp/email"

def send_email_via_brevo(to_email: str, subject: str, html_content: str):
    """
    Sends an email via Brevo HTTP API.
    Raises Exception containing Brevo response text on failure.
    """
    if not BREVO_API_KEY:
        raise Exception("BREVO_API_KEY is not set in this file")

    headers = {
        "accept": "application/json",
        "api-key": BREVO_API_KEY,
        "content-type": "application/json"
    }
    payload = {
        "sender": {"name": SENDER_NAME, "email": SENDER_EMAIL},
        "to": [{"email": to_email}],
        "subject": subject,
        "htmlContent": html_content
    }
    res = requests.post(BREVO_URL, headers=headers, json=payload, timeout=20)
    if res.status_code >= 300:
        print("Brevo error response:", res.status_code, res.text)
        # raise a detailed exception so callers can see the Brevo response
        raise Exception(f"Brevo error: {res.status_code} {res.text}")

    try:
        return res.json()
    except Exception:
        return {"raw": res.text}
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()
        password = (data.get("password") or "")

        if not email or not password:
            return jsonify({"message": "Missing email or password"}), 400

        user = collection.find_one({"email": email})
        if not user:
            return jsonify({"message": "User not found"}), 404

        db_password = user.get("password")
        if not db_password:
            return jsonify({"message": "Password not found in DB"}), 500

        if bcrypt.checkpw(password.encode('utf-8'), db_password.encode('utf-8')):
            return jsonify({
                "message": "Login successful",
                "user": {
                    "fullName": user.get("name"),
                    "email": user.get("email")
                }
            }), 200

        return jsonify({"message": "Invalid credentials"}), 401

    except Exception as e:
        print("Login error:", e)
        traceback.print_exc()
        return jsonify({"message": "Internal server error", "error": str(e)}), 500


@app.route('/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json() or {}
        name = (data.get('fullName') or "").strip()
        email = (data.get('email') or "").strip().lower()
        password = (data.get('password') or "")

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
        return jsonify({"message": "Internal server error", "error": str(e)}), 500


@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()

        if not email:
            return jsonify({"message": "Email is required"}), 400

        user = collection.find_one({"email": email})
        if not user:
            return jsonify({"message": "Email not found"}), 404

        otp = f"{random.randint(0, 999999):06d}"

        otp_collection.update_one(
            {"email": email},
            {"$set": {"otp": otp, "expiresAt": datetime.utcnow() + timedelta(minutes=5)}},
            upsert=True
        )

        subject = "Your VITA GO Password Reset OTP"
        name = user.get('name') or 'User'
        html = f"""
        <!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Password Reset OTP</title>
</head>
<body style="margin:0; padding:0; font-family: Arial, sans-serif; background-color:#f4f6f8;">
  <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f4f6f8; padding:20px 0;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff; border-radius:10px; box-shadow:0 4px 10px rgba(0,0,0,0.1); padding:30px;">
          
          <!-- Header -->
          <tr>
            <td align="center" style="padding-bottom:20px;">
              <h2 style="margin:0; color:#2a9d8f;">🔐 Password Reset</h2>
            </td>
          </tr>

          <!-- Greeting -->
          <tr>
            <td style="font-size:16px; color:#333333; padding-bottom:10px;">
              <p>Hello <strong>{name}</strong>,</p>
            </td>
          </tr>

          <!-- OTP Section -->
          <tr>
            <td style="font-size:16px; color:#333333; padding-bottom:20px;">
              <p>Your OTP for password reset is:</p>
              <p style="font-size:22px; font-weight:bold; color:#e63946; letter-spacing:2px; text-align:center; margin:20px 0;">
                {otp}
              </p>
              <p>This OTP is valid for <strong>5 minutes</strong>.</p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="font-size:14px; color:#555555; padding-top:20px; border-top:1px solid #eeeeee; text-align:center;">
              <p>— {SENDER_NAME}</p>
              <p style="font-size:12px; color:#999999;">If you didn’t request this, please ignore this email.</p>
            </td>
          </tr>

        </table>
      </td>
    </tr>
  </table>
</body>
</html>

        """
        try:
            send_email_via_brevo(email, subject, html)
        except Exception as send_err:
            print("Send email failed:", send_err)
            # return Brevo error to client for debugging
            return jsonify({"message": "Failed to send OTP email", "error": str(send_err)}), 500

        return jsonify({"message": "OTP sent to your email"}), 200

    except Exception as e:
        print("Forgot password error:", e)
        traceback.print_exc()
        return jsonify({"message": "Internal server error", "error": str(e)}), 500


@app.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json() or {}
        email = (data.get("email") or "").strip().lower()
        otp = (data.get("otp") or "").strip()
        new_password = (data.get("newPassword") or "")

        if not email or not otp or not new_password:
            return jsonify({"message": "Email, OTP and newPassword are required"}), 400

        otp_doc = otp_collection.find_one({"email": email})
        if not otp_doc:
            return jsonify({"message": "OTP not found. Please request a new one."}), 404

        expires_at = otp_doc.get("expiresAt")
        if not expires_at or datetime.utcnow() > expires_at:
            otp_collection.delete_one({"email": email})
            return jsonify({"message": "OTP expired. Please request a new one."}), 410

        if otp_doc.get("otp") != otp:
            return jsonify({"message": "Invalid OTP"}), 401

        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        collection.update_one(
            {"email": email},
            {"$set": {"password": hashed_password.decode('utf-8')}}
        )

        otp_collection.delete_one({"email": email})
        try:
            send_email_via_brevo(
                email,
f""" <table width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f4f6f8; padding:20px 0;">
  <tr>
    <td align="center">
      <table width="600" cellpadding="0" cellspacing="0" border="0" style="background:#ffffff; border-radius:10px; box-shadow:0 4px 12px rgba(0,0,0,0.1); padding:30px;">
        
        <!-- Header -->
        <tr>
          <td align="center" style="padding-bottom:20px;">
            <h2 style="margin:0; color:#264653;">✅ Password Updated</h2>
          </td>
        </tr>

        <!-- Message -->
        <tr>
          <td style="font-size:16px; color:#333333; line-height:1.6; padding-bottom:20px;">
            <p>Hello,</p>
            <p>Your <strong>VITA GO</strong> account password has been successfully updated.</p>
            <p>If this wasn’t you, please reset your password immediately or contact support.</p>
          </td>
        </tr>

        <!-- Security Note -->
        <tr>
          <td style="padding:20px; background:#f8f9fa; border:1px solid #e0e0e0; border-radius:8px; font-size:14px; color:#555555;">
            <p style="margin:0;">🔒 For your security, we recommend not sharing your password with anyone.</p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="font-size:14px; color:#555555; padding-top:20px; border-top:1px solid #eeeeee; text-align:center;">
            <p>— {SENDER_NAME}</p>
            <p style="font-size:12px; color:#999999;">This is an automated message. Please do not reply.</p>
          </td>
        </tr>

      </table>
    </td>
  </tr>
</table>
 """
            )
        except Exception as _e:
            print("Confirmation email error (non-fatal):", _e)

        return jsonify({"message": "Password reset successful"}), 200

    except Exception as e:
        print("Reset password error:", e)
        traceback.print_exc()
        return jsonify({"message": "Internal server error", "error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
