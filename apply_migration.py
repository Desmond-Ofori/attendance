import sys
sys.path.append('tapin_backend')

from tapin_backend.app import app
from tapin_backend.models import db
from alembic.config import Config
from alembic import command

with app.app_context():
    alembic_cfg = Config("tapin_backend/migrations/alembic.ini")
    command.upgrade(alembic_cfg, "head")
print("Migration applied successfully.")