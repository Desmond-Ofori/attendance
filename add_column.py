from tapin_backend.app import app
from tapin_backend.models import db

with app.app_context():
    db.session.execute(db.text('ALTER TABLE classes ADD COLUMN class_name VARCHAR(160)'))
    db.session.commit()
    print('Column added successfully')