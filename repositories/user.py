from flask_login import UserMixin

from repositories.template.mongoRepository import MongoRepository


repo = MongoRepository("users")


class User(UserMixin):
    def __init__(self, data):
        self.data = data
        self.id = data["google_id"] if "google_id" in data else data["tag_id"]
        self.role = "google" if "google_id" in data else "tag"

    @staticmethod
    def get(user_id):
        user_data = repo.read({"$or": [{"google_id": user_id}, {"$and": [{"tag_id": user_id}]}]})
        if not user_data:
            return None
        else:
            return User(user_data)

    @staticmethod
    def update_counter(tag_id, counter):
        result = repo.update({"tag_id": tag_id}, {"$set": {"counter": counter}})
        return result.modified_count > 0

    @staticmethod
    def create(data):
        repo.insert(data)
        return User(data)
