#!/bin/bash

sudo uvicorn main:wiapi --reload --host 0.0.0.0 --port 443 --ssl-keyfile keys/ssl_priv.pem --ssl-certfile keys/ssl_cert.crt
