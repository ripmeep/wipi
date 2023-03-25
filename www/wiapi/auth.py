import time
from functools import wraps
from jwt import JWT, jwk_from_pem
from wiapi.exceptions import WiapiHTTPException
from wiapi import wiapi, Request

class WiapiJWT(object):
    def __init__(self, keyfile='keys/jwt_priv.pem', pubkey='keys/jwt_pub.pem'):
        self.keyfile = keyfile
        self.pubkey = pubkey

    def parse(self, token: str):
        try:
            instance = JWT()

            with open(self.pubkey, 'rb') as pk:
                key = jwk_from_pem(pk.read())

            message = instance.decode(token, key, do_time_check=False)

            tn = time.time()
            te = message['exp']

            if (tn > te):
                return (False, message)

            return (True, message)
        except Exception as e:
            raise e
            return (False, None)

    def create_token(self, username, admin=False, expires=3600):
        instance = JWT()
        tn = time.time()

        message = {
            'exp': tn + 3600,
            'iat': tn,
            'username': username,
            'admin': admin
        }

        with open(self.keyfile, 'rb') as pk:
            key = jwk_from_pem(pk.read())

        jws = instance.encode(message, key, alg='RS256')

        return jws

def auth_required(func):
    @wraps(func)

    async def wrapper(*args, **kwargs):
        try:
            request = kwargs[list(filter(lambda r: type(kwargs[r]) == Request, kwargs.keys()))[0]]
            admin_required = kwargs.get('admin_required', False)

            jwt_token = request.headers.get('Authorization', False)

            if not jwt_token:
                raise Exception()

            wjwt = WiapiJWT()

            jwt_token = jwt_token.split("Bearer ")[1]
            valid, message = wjwt.parse(jwt_token)

            if not valid and message is not None:
                raise WiapiHTTPException(
                    status_code=401,
                    detail='Access token has expired'
                )

            if admin_required and not message['admin']:
                raise Exception()
        except WiapiHTTPException as e:
            raise e
        except:
            raise WiapiHTTPException(
                status_code=401,
                detail='Unauthorized'
            )

        return await func(*args, **kwargs)

    return wrapper
