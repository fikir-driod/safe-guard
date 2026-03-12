from app import app, db, User
app.app_context().push()
db.create_all()
users = User.query.all()
print('Users:', [(u.username, u.is_admin) for u in users])

