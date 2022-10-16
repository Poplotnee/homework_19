from dao.model.user import User


class UserDAO:
    def __init__(self, session):
        self.session = session

    def get_one(self, uid):
        return self.session.query(User).get(uid)

    def get_all(self):
        return self.session.query(User).all()

    def get_by_username(self, username):
        return self.session.query(User).filter(User.username == username).first()

    def create(self, upload_data):
        new_user = User(**upload_data)
        self.session.add(new_user)
        self.session.commit()
        return new_user

    def update(self, upload_data):
        uid = upload_data.get('uid')
        user = self.get_one(uid)
        user.username = upload_data.get('username')
        user.password = upload_data.get('password')
        user.role = upload_data.get('role')
        self.session.add(user)
        self.session.commit()

    def delete(self, uid):
        user = self.get_one(uid)
        self.session.delete(user)
        self.session.commit()
        return user
