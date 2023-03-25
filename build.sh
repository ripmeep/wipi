#!/bin/bash

if [ $UID -ne 0 ]; then
	echo "Please run this as root"
	exit
fi

function title()
{
	echo
	echo -e -n "\033[01;32m"
	echo -e "-------------- $1 --------------\033[0m"
}

DEFAULT_API_ADMIN_USERNAME="wipi"
DEFAULT_API_ADMIN_PASSWORD="wipi"


# System dependencies

title "Installing system dependencies"

sudo apt-get update
sudo apt-get install libcurl4-openssl-dev libiw-dev libsqlite3-dev -y # lib dependencies
sudo apt-get install python3-full python3-dev python3-pip python3-requests -y # python package dependencies
sudo apt-get install sqlite3 wireless-tools net-tools # sys bin tool dependencies


# Python3 modules

title "Installing python modules"

pip3 install fastapi[all]
pip3 install uvicorn[all]
pip3 install pydantic
pip3 install sqlite3


# Build & install python module

title "Building dev libraries"

pip3 install ./wipy


# API setup

title "Initializing & configuring API"

mkdir www/db
mkdir www/keys

rm www/db/wipi.db 2>/dev/null
touch www/db/wipi.db
sqlite3 www/db/wipi.db "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, admin INTEGER)"
sqlite3 www/db/wipi.db "CREATE TABLE jobs(id INTEGER PRIMARY KEY AUTOINCREMENT, interface TEXT NOT NULL, bssid TEXT NOT NULL, start INTEGER, packets INTEGER NOT NULL, delay INTEGER NOT NULL, complete INTEGER)"

python3 -c "import sqlite3, hashlib; conn = sqlite3.connect('www/db/wipi.db'); p = hashlib.sha256('${DEFAULT_API_ADMIN_PASSWORD}'.encode()).digest(); cur = conn.cursor(); cur.execute('INSERT INTO users(username, password, admin) VALUES(?, ?, ?)', (${DEFAULT_API_ADMIN_USERNAME}, p, 1,)); conn.commit()"

title "Generating JWT & SSL keys"

openssl genrsa -out www/keys/jwt_priv.pem 2048
openssl rsa -in www/keys/jwt_priv.pem -pubout -out www/keys/jwt_pub.pem
openssl req -x509 -newkey rsa:4096 -keyout www/keys/ssl_priv.pem -out www/keys/ssl_cert.pem -sha256 -days 730


title "Finished"
echo
