from flask import Flask
from users.user_manupulate import Users


def run_app():
    auth_app = Flask(__name__)
    Users(auth_app)
    return auth_app