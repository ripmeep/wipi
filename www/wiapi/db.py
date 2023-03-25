import sqlite3
import hashlib

class WiapiDatabase(object):
    def __init__(self, path="db/wiapi.db"):
        self.path = path
        self.conn = sqlite3.connect(self.path)
        self.cur = self.conn.cursor()

    def clear(self):
        try:
            self.cur.execute("DROP TABLE users")
        except:
            pass

        try:
            self.cur.execute("DROP TABLE jobs");
        except:
            pass

        self.cur.execute("CREATE TABLE users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password TEXT NOT NULL, admin INTEGER)")
        self.cur.execute("CREATE TABLE jobs(id INTEGER PRIMARY KEY AUTOINCREMENT, interface TEXT NOT NULL, bssid TEXT NOT NULL, start INTEGER, packets INTEGER NOT NULL, delay INTEGER NOT NULL, complete INTEGER)")

        self.conn.commit()

    def add_user(self, username, password, admin=False, digest=True) -> bool:
        try:
            password = password if not digest else hashlib.sha256(password.encode()).digest()

            self.cur.execute(
                "INSERT INTO users(username, password, admin) VALUES(?, ?, ?)",
                (username, password, 1 if admin else 0,)
            )

            self.conn.commit()

            return True
        except:
            pass

        return False

    def add_job(self, interface: str, bssid: str, start: int, packets: int, delay: int):
        try:
            self.cur.execute(
                "INSERT INTO jobs(interface, bssid, start, packets, delay, complete) VALUES(?, ?, ?, ?, ?, ?)",
                (interface, bssid, start, packets, delay, 0,)
            )

            self.conn.commit()
            self.cur.execute("SELECT * FROM jobs ORDER BY start DESC LIMIT 1")

            return self.cur.fetchall()
        except Exception as e:
            raise e

        return None

    def get_job(id=0, all=False):
        if all:
            self.cur.execute("SELECT * FROM jobs")

            return cur.fetchall()

        self.cur.execute("SELECT * FROM jobs WHERE id=?", (id,))

        return cur.fetchall()

    def check_credentials(self, username, password, digest=True) -> list:
        password = password if not digest else hashlib.sha256(password.encode()).digest()

        self.cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password,))

        fetched = self.cur.fetchall()

        if len(fetched) > 0:
            return [True, fetched[0]]

        return [False, ()]
