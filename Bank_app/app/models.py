from Bank_app.app import db_bank as db

class TransactionRecords(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    authenticated = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<ClientUser {self.username}>'

class TransactionTest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    authenticated = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f'<ClientUser {self.username}>'

