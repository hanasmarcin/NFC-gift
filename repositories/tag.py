from repositories.product import Product
from repositories.template.mongoRepository import MongoRepository

repo = MongoRepository("tags")


def get(tag_id):
    tag_data = repo.read({"tag_id": tag_id})
    if not tag_data:
        return None
    else:
        return tag_data


def get_visible(tag_id):
    tag_data = repo.read({"tag_id": tag_id, "visible": True})
    if not tag_data:
        return None
    else:
        return tag_data


def upload_gift_data(tag_id, data):
    if not _check_gift_data(data):
        raise Exception("Wrong data format")
    result = repo.update({"tag_id": tag_id}, {"$set": {"gift_data": data}})
    return result.matched_count


def assign_to_person(tag_id, person_id):
    result = repo.update(
        {"$and": [
            {"tag_id": tag_id},
            {"$or": [
                {"person_id": {"$exists": False}},
                {"person_id": None}]}]},
        {"$set": {"person_id": person_id}})
    return result.matched_count > 0


def get_all_for_person(person_id):
    return list(repo.read_many({"person_id": person_id}))


def create_empty(tag_id, product_id, purchase_date):
    product = Product.get(product_id)
    if not product:
        raise Exception("Product with given id does not exist")
    data = {
        "tag_id": tag_id,
        "product_name": product["name"],
        "purchase_date": purchase_date,
        "visible": False
    }
    if "image" in product:
        data["product_image"] = product["image"]

    repo.insert(data)
    return data


def _check_gift_data(data):
    if "video" in data and "file_path" not in data["video"]:
        return False
    elif "images" in data and not isinstance(data["images"], list):
        return False
    elif "images" in data and not all("file_path" in image for image in data["images"]):
        return False
    return True


def get_visible_tag_for_person(tag_id, person_id):
    return repo.read({"tag_id": tag_id, "person_id": person_id, "visible": True})


def delete_from_person(tag_id, person_id):
    result = repo.update(
        {"$and": [
            {"tag_id": tag_id},
            {"person_id": person_id}
               ]},
        {"$unset": {"person_id": person_id}})
    return result.modified_count > 0


def switch_visibility(tag_id, person_id, target_visibility):
    result = repo.update(
        {"$and": [
            {"tag_id": tag_id},
            {"person_id": person_id}
        ]},
        {"$set": {"visible": target_visibility}})

    return result.modified_count > 0
