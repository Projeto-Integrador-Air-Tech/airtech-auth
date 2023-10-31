from flask import Flask
from authentication.server_config import ServerConfig

def run_app():
    auth_app = Flask(__name__)
    ServerConfig(auth_app)
    return auth_app