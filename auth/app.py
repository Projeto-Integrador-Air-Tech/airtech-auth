import logging
from cheroot.wsgi import Server as WSGIServer, PathInfoDispatcher
from cheroot.ssl.builtin import BuiltinSSLAdapter
from authentication import run_app as run_auth_app
from users import run_app as run_user_app
from utils.settings import SSL_ON

AUTH_APP = run_auth_app()
USERS = run_user_app()
DISPATCHER = PathInfoDispatcher([('/auth', AUTH_APP), ('/user', USERS)])

if SSL_ON:
    PORT = 8043
    SERVER = WSGIServer(('0.0.0.0', PORT), DISPATCHER)
    SSL_CERT = "./secrets/ssl_certificate.crt"
    SSL_KEY = "./secrets/private_key.key"
    SERVER.ssl_adapter = BuiltinSSLAdapter(certificate=SSL_CERT, private_key=SSL_KEY)
else:
    PORT = 8080
    SERVER = WSGIServer(('0.0.0.0', PORT), DISPATCHER)

if __name__ == '__main__':
    logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info('Running server on port %s', PORT)
    SERVER.safe_start()
