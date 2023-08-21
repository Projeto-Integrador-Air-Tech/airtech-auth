import jwt
import json
from collections import defaultdict
from datetime import datetime, timedelta
from flask import request, abort, make_response, jsonify
from utils.settings import CONNECTION, TOKEN_SIZE


class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)



class JwtGen():
    def __init__(self, app):
        self.app = app
        app.route('/authenticate', methods=['POST'])(self.authenticate_api)
        app.route('/authorize', methods=['POST'])(self.authorize_api)
        app.json_encoder = CustomJSONEncoder

    def authenticate_api(self):
        token_api = request.data.decode()
        if not token_api:
            abort(make_response(
                jsonify(message="invalid token (o token in request)"), 400))
        if len(token_api) != TOKEN_SIZE:
            abort(make_response(
                jsonify(message="invalid token(wrong token length)"), 400))
        with CONNECTION as conn:
            cursor = conn.cursor()
            cursor.execute(
                'SELECT * FROM "authorization".api_token WHERE token = %s', (token_api,))
            result = cursor.fetchone()
            if result is None:
                abort(make_response(
                    jsonify(message="invalid token (token not found)"), 401))
            payload = {
                "email": result[3],
                "exp": datetime.utcnow() + timedelta(days=1),
                "iat": datetime.utcnow(),
                "username":  result[2],
                "sub": result[1]   # Defina o tempo de expiração desejado
            }
        with open('./secrets/private_key.pem', 'rb') as private_key_file:
            private_key = private_key_file.read()

        jwt_token = jwt.encode(payload, private_key, algorithm="RS256")
        return make_response(jwt_token, 200)

    def authorize_api(self, jwt_sha=None):
        if not jwt_sha:
            jwt_sha = request.data.decode()
            if not jwt_sha:
                abort(make_response(
                    jsonify(message="invalid token (no token in request)"), 400))
        try:
            with open('./secrets/public_key.pem', 'rb') as public_key_file:
                public_key = public_key_file.read()
                decoded_payload = jwt.decode(
                    jwt_sha, public_key, algorithms=["RS256"])
                user_id = decoded_payload.get("sub")
        except jwt.ExpiredSignatureError:
            abort(make_response(jsonify(message="token has expired"), 401))
        except jwt.DecodeError as decode_err:
            abort(make_response(jsonify(message="Invalid token format or padding error", error=str(decode_err)), 401))
        except Exception as e:
            abort(make_response(jsonify(message="An error occurred during decoding", error=str(e)), 500))

        with CONNECTION as conn:
            cursor = conn.cursor()
            cursor.execute(
                ' SELECT au.access_user_id, au.user_id, ap.access_profiles_id, au.created_at,'
                ' p.permission_name, pr.profile_name '
                'FROM "authorization".access_user AS au '
                'INNER JOIN "authorization".access_profiles AS ap ON au.access_profiles_id = ap.access_profiles_id '
                'INNER JOIN "authorization".permissions AS p ON ap.permission_id = p.permission_id '
                'INNER JOIN "authorization".profiles AS pr ON ap.profile_id = pr.profile_id '
                'WHERE au.user_id = %s;', (user_id,)
            )
        result = cursor.fetchall()
        permissions_data = defaultdict(list)

        for row in result:
            permission_name = row[4]
            profile_name = row[5]
            permissions_data[permission_name].append(profile_name)

        permissions_dict = {}
        for permission_name, profiles in permissions_data.items():
            permissions_dict[permission_name] = profiles

        cursor.execute(
            f' SELECT email, username  from "control".users WHERE user_id = {user_id}'
        )
        result_name_email = cursor.fetchone()

        payload = {
            "email": result_name_email[0],
            "exp": (datetime.utcnow() + timedelta(days=1)).isoformat(),
            "acesses": permissions_dict,
            "iat": datetime.utcnow().isoformat(),
            "username": result_name_email[1],
            "sub": user_id
        }

        with open('./secrets/private_key.pem', 'rb') as private_key_file:
            private_key = private_key_file.read()

        jwt_token = jwt.encode(payload, private_key, algorithm="RS256")

        return make_response(jwt_token, 200)
