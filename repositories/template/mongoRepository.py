import ssl
import uuid

from pymongo import MongoClient

PASSWORD = "8EGEQ3kl2uCTEn0k"
MONGO_URL = f"mongodb+srv://admin:{PASSWORD}@cluster0.jlcit.mongodb.net/myFirstDatabase?retryWrites=true&w=majority"


class MongoRepository(object):
    def __init__(self, repo_name):
        client = MongoClient(MONGO_URL, ssl_cert_reqs=ssl.CERT_NONE)

        database = client.get_database("nfc-gifts")
        self.repo = getattr(database, repo_name)

    # Create operations
    def insert(self, item):
        return self.repo.insert_one(item)

    def insert_many(self, items):
        return self.repo.insert_many(items)

    # Read operations
    def read_all(self):
        return self.repo.find()

    def read_many(self, conditions):
        return self.repo.find(conditions)

    def read(self, conditions):
        return self.repo.find_one(conditions)

    # Update operations
    def update(self, conditions, new_value):
        return self.repo.update_one(conditions, new_value)

    def remove(self, conditions):
        return self.repo.delete_one(conditions)


user = {
    "google_id": uuid.uuid4(),
    "name": "test name",
    "email": "test_email",
    "profile_pic": "test_pic"
}

# repo = ProductsRepository()
# repo.insert(product)
# print(repo.read_all())
