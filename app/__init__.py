from flask import Flask
from flask_mysqldb import MySQL
from flask_login import LoginManager

app = Flask(__name__)
app.secret_key = 'super_secret_key'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'music_review'

mysql = MySQL(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Zaloguj się, aby uzyskać dostęp do tej strony."

from app import routes