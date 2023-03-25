from fastapi import FastAPI, Request

wiapi = FastAPI(ssl_keyfile='keys/ssl_priv.pem', ssl_certfile='keys/ssl_cert.crt')

