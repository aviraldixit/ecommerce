from flask import Flask
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager
from flask_bootstrap import Bootstrap
from flask_uploads import UploadSet, configure_uploads, IMAGES
from werkzeug.utils import import_string


app = Flask(__name__)
if app.config["ENV"] == "production":
    cfg = import_string('config.config.ProductionConfig')()
    app.config.from_object(cfg)
else:
    cfg = import_string('config.config.DevelopmentConfig')()
    app.config.from_object(cfg)

print(f' Flask ENV is set to: {app.config["ENV"]}')


photos = UploadSet('photos', IMAGES)

configure_uploads(app, photos)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

manager = Manager(app)
manager.add_command('db', MigrateCommand)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

bootstrap = Bootstrap(app)

from views import *
from models import *


def init_db(choice):
    if choice == 1:
        db.create_all()
        print('Tables created')
    elif choice == 2:
        db.drop_all()
        print('Tables Dropped')
    else:
        print('Do nothing!!')


if __name__ == '__main__':
    init_db(3)
    print(app.config['ENV'])
    app.run()
