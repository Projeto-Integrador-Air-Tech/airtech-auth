import os
from distutils.util import strtobool
from utils.postgresql_adapiter import PostgreSQLConnection
from dotenv import load_dotenv

load_dotenv()

TOKEN_SIZE = int(os.environ.get('TOKEN_SIZE', 45))
PATH_PRIVATE_KEY = str(os.environ.get('PATH_PRIVATE_KEY'))
SALT = str(os.environ.get('SALT'))
SSL_ON = bool(strtobool(str(os.environ.get('SSL_ON',False))))
POSTGRESQL_HOST = str(os.environ.get('POSTGRESQL_HOST'))
POSTGRESQL_USER = str(os.environ.get('POSTGRESQL_USER'))
POSTGRESQL_PORT = str(os.environ.get('POSTGRESQL_PORT'))
POSTGRESQL_PW = str(os.environ.get('POSTGRESQL_PW'))
POSTGRESQL_DB = str(os.environ.get('POSTGRESQL_DB'))
CONNECTION = PostgreSQLConnection(
    host= POSTGRESQL_HOST,
    port= POSTGRESQL_PORT,
    database= POSTGRESQL_DB,
    user= POSTGRESQL_USER,
    password= POSTGRESQL_PW
) 