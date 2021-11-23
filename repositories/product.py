import uuid

from repositories.template.mongoRepository import MongoRepository

repo = MongoRepository("products")


class Product:
    def __init__(self, data):
        self.data = data

    @staticmethod
    def get(product_id):
        product_data = repo.read({"product_id": product_id})

        if not product_data:
            return None
        else:
            return Product(product_data)

    @staticmethod
    def create(data):
        if not Product.check_data(data):
            raise Exception("Bad data")
        repo.insert(data)
        return Product(data)

    @staticmethod
    def check_data(data):
        return "name" in data and "product_id" in data


product = {
    "tag_id": uuid.uuid4(),
    "name": "test name",
    "purchase_date": "test_date",
    "picture": "test_pic"
}
