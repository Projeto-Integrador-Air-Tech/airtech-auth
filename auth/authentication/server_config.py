from authentication.jwt_manupulate import JwtGen

class ServerConfig():

    PATH_PRIVATE_KEY = './secrets/private_key.pem'

    def __init__(self, app):
        s_c = app.config
        s_c['SECRET_KEY'] = self.load_private_key()
        JwtGen(app)


    @staticmethod
    def load_private_key():
        with open(ServerConfig.PATH_PRIVATE_KEY, 'rb') as pem_file:
            return pem_file.read()
