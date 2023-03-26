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


echo -e "\n\033[01;33m _     _  ___   _______  ___  \n| | _ | ||   | |       ||   | \n| || || ||   | |    _  ||   | \n|       ||   | |   |_| ||   | \n|       ||   | |    ___||   | \n|   _   ||   | |   |    |   | \n|__| |__||___| |___|    |___| \033[0m\n"


# System dependencies

title "Installing system dependencies"

sudo apt-get update
sudo apt-get install libiw-dev libsqlite3-dev libffi-dev -y # lib dependencies
sudo apt-get install python3-full python3-dev python3-pip python3-requests -y # python package dependencies
sudo apt-get install sqlite3 wireless-tools net-tools -y # sys bin tool dependencies


# Python3 modules

title "Installing python modules"

pip3 install fastapi[all]
pip3 install uvicorn[all]
pip3 install pydantic
pip3 install jwt


# Build & install python module

title "Building dev libraries"

cd wipy

python3 setup.py build
python3 setup.py install

cd ..


# API setup

title "Initializing & configuring API"

mkdir www/db
mkdir www/keys

rm www/db/wiapi.db 2>/dev/null
touch www/db/wiapi.db
sqlite3 www/db/wiapi.db "CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, admin INTEGER)"
sqlite3 www/db/wiapi.db "CREATE TABLE jobs(id INTEGER PRIMARY KEY AUTOINCREMENT, interface TEXT NOT NULL, bssid TEXT NOT NULL, start INTEGER, packets INTEGER NOT NULL, delay INTEGER NOT NULL, complete INTEGER)"

python3 -c "import sqlite3, hashlib; conn = sqlite3.connect('www/db/wiapi.db'); p = hashlib.sha256('${DEFAULT_API_ADMIN_PASSWORD}'.encode()).digest(); cur = conn.cursor(); cur.execute('INSERT INTO users(username, password, admin) VALUES(?, ?, ?)', ('${DEFAULT_API_ADMIN_USERNAME}', p, 1,)); conn.commit()"

chmod +x www/start.sh
chmod +x www/scripts/monitor_mode.sh

echo "Finished"


# API server-side keys

title "Generating JWT & SSL keys"

openssl genrsa -out www/keys/jwt_priv.pem 2048
openssl rsa -in www/keys/jwt_priv.pem -pubout -out www/keys/jwt_pub.pem
openssl req -x509 -newkey rsa:4096 -keyout www/keys/ssl_priv.pem -out www/keys/ssl_cert.crt -sha256 -days 730 -nodes -subj '/CN=www.meep.rip/O=ripmeep/C=US'


title "Finished"
echo
