from flask_login import UserMixin
from app import mysql, login_manager

class User(UserMixin):
    def __init__(self, id, username, password, is_admin=False):
        self.id = id
        self.username = username
        self.password = password
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    cursor = mysql.connection.cursor()
    result = cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
    if result > 0:
        data = cursor.fetchone()
        return User(id=data[0], username=data[1], password=data[2], is_admin=bool(data[3]))
    return None
