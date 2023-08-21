import jwt
import re
import base64
import hashlib
from datetime import datetime
from functools import wraps
from flask import request, abort, make_response, jsonify
from utils.hash_salt import GenerateHashes
from utils.settings import CONNECTION

GENSHAS = GenerateHashes()


class Users:

    def __init__(self, app):
        self.app = app
        app.route('/create', methods=['POST'])(self.create_user)
        app.route('/update', methods=['PUT'])(self.update_user)
        app.route('/login', methods=['POST'])(self.update_user)

    @staticmethod
    def is_email_taken(email, cursor):
        cursor.execute(
            'SELECT email FROM "authorization".users WHERE email = %s', (email,))
        return cursor.fetchone() is not None

    def create_user(self):
        data = request.form
        if not data:
            abort(make_response(jsonify(message="Invalid data"), 400))

        email = data.get('email')
        if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            abort(make_response(jsonify(message="Invalid email format"), 400))

        with CONNECTION as conn:
            cursor = conn.cursor()
            if self.is_email_taken(email, cursor):
                abort(make_response(jsonify(message="Email already taken"), 400))

            birth_date = data.get('birth date')
            if birth_date:
                try:
                    data_dmy = datetime.strptime(birth_date, '%d-%m-%Y')
                    data_ymd = data_dmy.strftime('%Y-%m-%d')
                    birth_date = data_ymd
                except ValueError:
                    abort(make_response(
                        jsonify(message="Invalid date_of_birth format"), 400))
            else:
                birth_date = None

            for key, value in data.items():
                if isinstance(value, str) and (";" in value or "--" in value):
                    abort(make_response(
                        jsonify(message="Possible SQL injection detected"), 400))

            cursor.execute(
                'INSERT INTO "authorization".users (user_id, username, email, password_hash, full_name, date_of_birth, registration_date, users_status) '
                "SELECT COALESCE(MAX(user_id), 0) + 1, %s, %s, %s, %s, %s, %s, %s "
                'FROM "authorization".users',
                (data['Username'], data['email'], GENSHAS.genrate_sha(password=data['password']),data['full name'], birth_date, datetime.now(), 'active')
            )
            conn.commit()

            token_api = GENSHAS.generate_token()
            encrypted_token = GENSHAS.genrate_sha(token_api)
            cursor.execute(
                'SELECT user_id FROM "authorization".users ORDER BY user_id DESC LIMIT 1;'
            )
            user_id = cursor.fetchone()
            cursor.execute(
                'INSERT INTO "authorization".api_token(token, user_id, username, email) VALUES'
                "(%s,%s, %s, %s) ",
                (encrypted_token, user_id, data['Username'], data['email'])
            )
            conn.commit()

        return jsonify({'message': f'User created id:{user_id[0]}', 'token': token_api}), 201

    def update_user(self):
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            public_key_path = './secrets/public_key.pem'
            try:
                with open(public_key_path, 'r') as f:
                    public_key = f.read()
                    decoded_token = jwt.decode(
                        token,
                        public_key,
                        algorithms=['RS256'],
                        options={"verify_aud": False}
                    )
                    return jsonify({'message': 'Authorized'}), 200
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token expired'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Invalid token'}), 401
        else:
            return jsonify({'message': 'Missing or invalid token'}), 401

    def login_user(self):
        auth_header = request.headers.get('Authorization')

        if auth_header:
            auth_type, auth_string = auth_header.split(' ')

            if auth_type.lower() == 'basic':
                try:
                    decoded_auth = base64.b64decode(auth_string).decode('utf-8')
                    username, password = decoded_auth.split(':')

                    with CONNECTION as conn:
                        cursor = conn.cursor()
                        cursor.execute("SELECT username, password_hash FROM authorization.users WHERE username = %s", (username,))
                        user_data = cursor.fetchone()

                    if user_data:
                        stored_password_hash = user_data[1]
                        # Hash the provided password and compare it with the stored hash
                        provided_password_hash = GENSHAS.genrate_sha(password)
                        if provided_password_hash == stored_password_hash:
                            return make_response("Login successful", status=200)
                        else:
                            return make_response("Invalid credentials", status=401)
                    else:
                        return make_response("User not found", status=401)
                except:
                    return make_response("Invalid authorization header", status=400)

        return make_response("Authorization required", status=401)
