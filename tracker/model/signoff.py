from tracker import db


class Signoff(db.Model):

    __tablename__ = 'signoff'
    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True, autoincrement=True)
    advisory = db.Column(db.Integer(), db.ForeignKey('advisory.id'))
    text = db.Column(db.String(128), default='', nullable=True)
    user = db.Column(db.Integer(), db.ForeignKey('user.id'))
    approved = db.Column(db.Boolean(), nullable=False, default=False)


    def __repr__(self):
        return '<Signoff {}>'.format(self.id)
