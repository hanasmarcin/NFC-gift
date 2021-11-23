import datetime
import os
from functools import wraps

from bson import json_util
from flask import Flask, render_template, url_for, Response, session, request, redirect, json, jsonify
from flask_login import LoginManager, current_user, login_user, logout_user
from oauthlib.oauth2 import WebApplicationClient
import requests
from werkzeug.exceptions import BadRequest
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import re
import mimetypes

from repositories.product import Product
import repositories.tag as tag_repo
from repositories.user import User
from config import *
from sdm.libsdm import *

app = Flask(__name__)
app.secret_key = APP_SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["REMEMBER_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["SESSION_PERMANENT"] = False
app.config['UPLOAD_FOLDER'] = "./uploads"
app.config['PREFERRED_URL_SCHEME'] = "https"

# Flask app setup
# app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# User session management setup
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)


# handler = logging.StreamHandler(sys.stdout)
# app.logger.addHandler(handler)


# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


def login_required(role):
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role != role and role != "ANY":
                return login_manager.unauthorized()
            return fn(*args, **kwargs)

        return decorated_view

    return wrapper


# background process happening without any refreshing
@app.route('/get_product_for_tag')
@login_required(role="google")
def get_product_for_tag():
    tag_id = request.args["tag_id"]
    if tag_repo.assign_to_person(tag_id, current_user.data["google_id"]):
        tag_data = tag_repo.get(tag_id)
        tag_data["product"] = Product.get(tag_data["product_id"]).data
        if "purchase_date" in tag_data:
            tag_data["purchase_date_str"] = '{d.month}/{d.day}/{d.year}'.format(d=tag_data["purchase_date"])
        return jsonify(json_util.dumps(tag_data))
    else:
        raise BadRequest("Tag already assigned to different user")


@app.route('/delete_tag_for_user')
@login_required(role="google")
def delete_tag_for_user():
    tag_id = request.args["tag_id"]
    return jsonify(tag_repo.delete_from_person(tag_id, current_user.data["google_id"]))


@app.route('/switch_tag_visibility')
@login_required(role="google")
def switch_tag_visibility():
    tag_id = request.args["tag_id"]
    target_visibility = json.loads(request.args.get("target_visibility", "false"))
    result = tag_repo.switch_visibility(tag_id, current_user.data["google_id"], target_visibility)
    return jsonify(result), 200 if result else 404


@app.route("/")
def index():
    if current_user.is_authenticated and current_user.role == "google":
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.data["name"], current_user.data["email"], current_user.data["profile_pic"]
            )
        )
    else:
        return render_template("home.html")


@app.route("/panel")
@login_required(role="google")
def user_panel():
    person_id = current_user.data["google_id"]
    tags = tag_repo.get_all_for_person(person_id)
    for tag in tags:
        tag["product"] = Product.get(tag["product_id"]).data
        if "purchase_date" in tag:
            tag["purchase_date_str"] = '{d.month}/{d.day}/{d.year}'.format(d=tag["purchase_date"])
    return render_template("user_panel.html", tags=tags)


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


@app.route("/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = "https://www.googleapis.com/oauth2/v4/token"

    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # app, and now you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Create a user in your db with the information provided
    # by Google
    user_data = {"google_id": unique_id,
                 "name": users_name,
                 "email": users_email,
                 "profile_pic": picture}

    user = User.get(unique_id)
    # Doesn't exist? Add it to the database.
    if not user:
        user = User.create(user_data)

    # Begin user session by logging the user in
    login_user(user)

    # Send user back to homepage
    return redirect(url_for("user_panel"))


@app.route("/logout")
@login_required(role="google")
def logout():
    logout_user()
    return redirect(url_for("index"))


@app.route('/res')
@login_required(role="ANY")
def get_resource():
    tag = get_tag_from_user()
    if not tag:
        raise BadRequest('User not logged in')

    res_name = request.args["name"]
    mimetype = request.args["type"]
    if not res_name or not mimetype:
        raise BadRequest('Video name not given')

    if not tag.get('gift_data') or not ('images' in tag['gift_data'] and
                                        (any(image['file_path'] == res_name for image in tag['gift_data']['images'])) or
                                        ('video' in tag['gift_data'] and
                                         tag['gift_data']['video']['file_path'] == res_name)):
        raise BadRequest('Resource unavailable')

    return Response(open(res_name, "rb"), mimetype=mimetype)


def get_tag_from_user():
    if current_user.is_active:
        if current_user.role == "google":
            if "tag_id" not in session:
                tag_id = request.args.get("tag_id")
                tag = tag_repo.get_visible_tag_for_person(tag_id, current_user.data["google_id"])
                if not tag:
                    raise BadRequest('No tag has been chosen')
                session["tag_id"] = tag_id
                return tag
            else:
                tag = tag_repo.get_visible_tag_for_person(session["tag_id"], current_user.data["google_id"])
                if not tag:
                    raise BadRequest('Tag could not be obtained')
                else:
                    return tag
        elif current_user.role == "tag":
            tag = tag_repo.get_visible(current_user.data["tag_id"])
            if not tag:
                raise BadRequest('Tag could not be obtained')
            else:
                return tag
    else:
        return None


@app.route('/gift')
def gift():
    result = get_tag_from_user().get('gift_data', {})
    # if not result:
    #     tag_id = request.args["tag_id"]
    #
    #     user = User({"tag_id": tag_id,
    #                  "counter": 1})
    #     if not User.get(tag_id):
    #         User.create(user.data)
    #
    #     login_user(user)
    #     result = tag_repo.get(tag_id)

    if "images" in result:
        for image in result["images"]:
            if "file_path" not in image or not os.path.exists(image["file_path"]):
                image["missing"] = True

    if "video" in result:
        if "file_path" not in result["video"] or not os.path.exists(result["video"]["file_path"]):
            result["video"]["missing"] = True

    return render_template("base.html", data=result)


@app.route('/upload', methods=["GET", "POST"])
@login_required(role="google")
def upload():
    req = request.form
    tag_id = request.args.get("tag_id")
    if request.method == "POST":

        data = {}
        data.update({key: value for key, value in req.items() if key in ("message", "sender")})
        files = request.files
        res_path = os.path.join(app.config['UPLOAD_FOLDER'], req["tag_id"])
        if os.path.exists(res_path):
            saved_files = os.listdir(res_path)
            for file_name in saved_files:
                file_path = os.path.join(res_path, secure_filename(file_name))
                if re.match("image", mimetypes.guess_type(file_path)[0]):
                    found_file = [re.match("(pre_image)(\d+)", key).group(2) for key, value in req.items()
                                  if re.match("pre_image\d+", key) and value == file_name]
                    if len(found_file) > 0:
                        if "images" not in data:
                            data["images"] = []
                        description = req.get(f"pre_image_desc{found_file[0]}", None)
                        if description:
                            data["images"].append({
                                "file_path": file_path,
                                "file_name": file_name,
                                "mimetype": mimetypes.guess_type(file_path)[0],
                                "description": description
                            })
                        else:
                            data["images"].append({
                                "file_path": file_path,
                                "file_name": file_name,
                                "mimetype": mimetypes.guess_type(file_path)[0],
                            })
                    else:
                        os.remove(file_path)
                elif re.match("video", mimetypes.guess_type(file_path)[0]):
                    found_file = [value for key, value in req.items()
                                  if re.match("pre_video", key) and value == file_name]
                    if len(found_file) > 0:
                        description = req.get("pre_video_desc", None)
                        if description:
                            data["video"] = {
                                "file_path": file_path,
                                "file_name": file_name,
                                "mimetype": mimetypes.guess_type(file_path)[0],
                                "description": description
                            }
                        else:
                            data["video"] = {
                                "file_path": file_path,
                                "file_name": file_name,
                                "mimetype": mimetypes.guess_type(file_path)[0],
                            }
                    else:
                        os.remove(file_path)

        for res_id, res in files.items():
            if res.mimetype == 'application/octet-stream':
                continue
            res_path = os.path.join(app.config['UPLOAD_FOLDER'], req["tag_id"])
            if not os.path.exists(res_path):
                os.makedirs(res_path)
            filename = os.path.join(res_path, secure_filename(res.filename))
            res.save(filename)
            if os.path.exists(filename):
                if "image" in res.mimetype:
                    i = int(res_id.split("image", 1)[1])
                    if "images" not in data:
                        data["images"] = []

                    description = req.get(f"image_desc{i}", None)
                    if description:
                        data["images"].append({
                            "file_path": filename,
                            "file_name": secure_filename(res.filename),
                            "mimetype": res.mimetype,
                            "description": description
                        })
                    else:
                        data["images"].append({
                            "file_path": filename,
                            "file_name": secure_filename(res.filename),
                            "mimetype": res.mimetype,
                        })
                elif "video" in res.mimetype:
                    description = req.get("video_desc", None)
                    if description:
                        data["video"] = {
                            "file_path": filename,
                            "file_name": secure_filename(res.filename),
                            "mimetype": res.mimetype,
                            "description": description
                        }
                    else:
                        data["video"] = {
                            "file_path": filename,
                            "file_name": secure_filename(res.filename),
                            "mimetype": res.mimetype
                        }

        tag_repo.upload_gift_data(req['tag_id'], data)
        session["tag_id"] = req['tag_id']
        return redirect("gift")

    gift_data = tag_repo.get(tag_id).get("gift_data", {}) if tag_id is not None else None
    if tag_id:
        gift_data["tag_id"] = tag_id
    return render_template("upload.html", gift=gift_data)


@app.context_processor
def utility_functions():
    def print_in_console(message):
        print(str(message))

    return dict(mdebug=print_in_console)


@app.route('/tag')
def internal_sdm():
    """
    SUN decrypting/validating endpoint.
    """
    enc_picc_data = request.args.get(ENC_PICC_DATA_PARAM)
    enc_file_data = request.args.get(ENC_FILE_DATA_PARAM)
    sdmmac = request.args.get(SDMMAC_PARAM)

    if not enc_picc_data:
        raise BadRequest(f"Parameter {ENC_PICC_DATA_PARAM} is required")

    if not sdmmac:
        raise BadRequest(f"Parameter {SDMMAC_PARAM} is required")

    try:
        enc_file_data_b = None
        enc_picc_data_b = binascii.unhexlify(enc_picc_data)
        sdmmac_b = binascii.unhexlify(sdmmac)

        if enc_file_data:
            enc_file_data_b = binascii.unhexlify(enc_file_data)
    except binascii.Error:
        raise BadRequest("Failed to decode parameters.")

    try:
        res = decrypt_sun_message(sdm_meta_read_key=SDM_META_READ_KEY,
                                  sdm_file_read_key=SDM_FILE_READ_KEY,
                                  picc_enc_data=enc_picc_data_b,
                                  sdmmac=sdmmac_b,
                                  enc_file_data=enc_file_data_b)
    except InvalidMessage:
        raise BadRequest("Invalid message (most probably wrong signature).")

    nfc_data = {'picc_data_tag': res[0].hex(), 'uid': res[1].hex(), 'read_ctr_num': res[2]}

    if res[3]:
        tag_data = res[3].decode('utf-8', 'ignore').split('_')
        tag_id = tag_data[0]
        tag_secret = tag_data[1]

        if tag_secret != TAG_SECRET:
            raise BadRequest("Invalid message (wrong signature).")
        counter = int(nfc_data["read_ctr_num"])
        user = User({"tag_id": tag_id,
                     "counter": 0})
        db_user = User.get(tag_id)
        if not db_user:
            User.create(user.data)
        elif db_user.data["counter"] >= counter:
            raise BadRequest("Invalid message (wrong signature).")

        user.data["counter"] = counter
        User.update_counter(tag_id, counter)
        login_user(user, duration=datetime.timedelta(minutes=1))
        return redirect(url_for("gift", tag_id=tag_id))

    return json_util.dumps(nfc_data)


if __name__ == '__main__':
    # app.run(ssl_context="adhoc")
    app.run(ssl_context="adhoc", debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
