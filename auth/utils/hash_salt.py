import secrets
import string
import bcrypt
from utils.settings import SALT, TOKEN_SIZE


class GenerateHashes:
    def genrate_sha(self, token):
        return str(bcrypt.kdf(
            password=token.encode('utf-8'),
            salt=SALT.encode('utf-8'),
            desired_key_bytes=32,
            rounds=len(SALT)**2))
    def generate_token(self):
        characters = string.ascii_letters + string.digits
        token = ''.join(secrets.choice(characters) for _ in range(TOKEN_SIZE))
        GenerateHashes().genrate_sha
        return token
