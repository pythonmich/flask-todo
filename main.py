import datetime
import os
from typing import Tuple
from functools import wraps
import pytz
import jwt
from flask import Flask, request, jsonify, Response, make_response
import uuid
import bcrypt
from sqlalchemy import DateTime, VARCHAR
from http import HTTPStatus
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

user = os.getenv("PSQL_USER")
password = os.getenv("PSQL_PASS")

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = f"postgresql://{user}:{password}@localhost:5432/flask_todo"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
db.init_app(app)

key = "secretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecret"


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(80), nullable=False)
    password = db.Column(VARCHAR(100), nullable=False)
    admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(DateTime(timezone=True), nullable=False,
                           default=datetime.datetime.now(tz=pytz.timezone("Africa/Nairobi")))


class Todo(db.Model):
    __tablename__ = "todo"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(80), nullable=False)
    completed = db.Column(db.Boolean, nullable=False, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    created_at = db.Column(DateTime(timezone=True), nullable=False,
                           default=datetime.datetime.now(tz=pytz.timezone("Africa/Nairobi")))


def authorize_user(func):
    wraps(func)

    def jwt_verify(*args, **kwargs):
        token = None
        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]
        if not token:
            return jsonify({"message": "token is missing"}), HTTPStatus.UNAUTHORIZED
        try:
            payload = jwt.decode(token, key, algorithms="HS256")
            user = User.query.filter_by(public_id=payload["id"]).first()
        except jwt.ExpiredSignatureError:
            return jsonify({"message": 'invalid token expired'})
        except jwt.InvalidTokenError:
            return jsonify({"message": 'invalid token provided'})

        return func(user, *args, **kwargs)

    jwt_verify.__name__ = func.__name__
    return jwt_verify


@app.route("/users", methods=["GET"])
@authorize_user
def get_all_users(current_user: User):
    if not current_user.admin:
        return jsonify({"message": "cannot perform function"}), HTTPStatus.FORBIDDEN
    users = User.query.all()
    results = []
    for user in users:
        user_data = {
            "public_id": user.public_id,
            "name": user.name,
            "password": user.password,
            "admin": user.admin,
            "created_at": user.created_at
        }
        results.append(user_data)
    return jsonify("users", results)


@app.route("/users/<public_id>", methods=["GET"])
@authorize_user
def get_user(current_user: User, public_id: str):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "no user found"}), HTTPStatus.NOT_FOUND

    if not current_user.admin:
        if current_user.public_id != user.public_id:
            return jsonify({"message": "cannot perform function"}), HTTPStatus.FORBIDDEN

    user_response = {
        "public_id": user.public_id,
        "name": user.name,
        "password": user.password,
        "admin": user.admin,
        "created_at": user.created_at
    }
    return jsonify(user_response), HTTPStatus.OK


@app.route("/users", methods=["POST"])
def create_user() -> Tuple[Response, int]:
    data = request.get_json()
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(data["password"].encode("utf-8"), salt)
    user_req = User(
        public_id=str(uuid.uuid4()),
        name=data["name"],
        password=hashed_password.decode("utf-8"),
    )
    db.session.add(user_req)
    db.session.commit()
    user = User.query.filter_by(public_id=user_req.public_id).first()
    user_response = {
        "public_id": user.public_id,
        "name": user.name,
        "admin": user.admin,
        "created_at": user.created_at
    }
    return jsonify(user_response), HTTPStatus.OK


@app.route("/users/<public_id>", methods=["PUT"])
@authorize_user
def promote_user(current_user: User, public_id: str):
    if not current_user.admin:
        return jsonify({"message": "cannot perform function"}), HTTPStatus.FORBIDDEN
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "no user found"}), HTTPStatus.NOT_FOUND
    user.admin = True
    db.session.commit()
    user_response = {
        "public_id": user.public_id,
        "name": user.name,
        "admin": user.admin,
    }
    return jsonify(user_response), HTTPStatus.OK


@app.route("/users/<public_id>", methods=["DELETE"])
@authorize_user
def delete_user(current_user, public_id: str):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"message": "no user found"}), HTTPStatus.NOT_FOUND

    if not current_user.admin:
        if current_user.public_id != user.public_id:
            return jsonify({"message": "cannot perform function"}), HTTPStatus.FORBIDDEN

    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "deleted"})


@app.route("/login", methods=["POST"])
def login_user():
    auth = request.authorization
    if not auth or not auth.password or not auth.username:
        return make_response("Could not verify user", HTTPStatus.UNAUTHORIZED,
                             {'WWW-Authenticate': 'Basic realm="Login required!"'})

    user = User.query.filter_by(name=auth.username).first()
    if not user:
        return jsonify({"message": "no user found"}), HTTPStatus.NOT_FOUND

    if bcrypt.checkpw(auth.password.encode("utf-8"), user.password.encode("utf-8")):
        payload = {
            "id": user.public_id,
            "issued_at": default(datetime.datetime.now(tz=pytz.timezone("Africa/Nairobi"))),
            "expired_at": default(
                datetime.datetime.now(tz=pytz.timezone("Africa/Nairobi")).__add__(datetime.timedelta(minutes=30)))
        }
        token = jwt.encode(payload,
                           key=key,
                           algorithm="HS256")
        return jsonify({"token": token})

    return make_response("Could not verify user", HTTPStatus.UNAUTHORIZED,
                         {'WWW-Authenticate': 'Basic realm="Login required!"'})


def default(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()


@app.route("/todo", methods=["GET"])
@authorize_user
def get_all_todo(current_user: User):
    todos = Todo.query.filter_by(user_id=current_user.id).all()

    results = []
    for todo in todos:
        todo_data = {
            "id": todo.id,
            "text": todo.text,
            "completed": todo.completed,
            "created_at": todo.created_at
        }
        results.append(todo_data)
    return jsonify({"todos": results})


@app.route("/todo/<todo_id>", methods=["GET"])
@authorize_user
def get_todo(current_user: User, todo_id: str):
    todo = Todo.query.filter_by(todo_id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({"message": "not todos"})

    todo_resp = {
        "id": todo.id,
        "text": todo.text,
        "completed": todo.completed,
        "created_at": todo.created_at
    }
    return jsonify(todo_resp)


@app.route("/todo", methods=["POST"])
@authorize_user
def create_todo(current_user: User):
    data = request.get_json()
    todo_req = Todo(text=data["text"], user_id=current_user.id)
    db.session.add(todo_req)
    db.session.commit()
    todo = Todo.query.filter_by(id=todo_req.id).first()
    todo_resp = {
        "id": todo.id,
        "text": todo.text,
        "completed": todo.completed,
        "created_at": todo.created_at
    }

    return jsonify(todo_resp)


@app.route("/todo/<todo_id>", methods=["PUT"])
@authorize_user
def complete_todo(current_user: User, todo_id: str):
    todo = Todo.query.filter_by(todo_id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({"message": "not todos"})

    todo.completed = True
    db.session.commit()
    todo_resp = {
        "id": todo.id,
        "text": todo.text,
        "completed": todo.completed,
        "created_at": todo.created_at
    }
    return jsonify(todo_resp)


@app.route("/todo/<todo_id>", methods=["DELETE"])
@authorize_user
def delete_todo(current_user: User, todo_id: str):
    todo = Todo.query.filter_by(todo_id=todo_id, user_id=current_user.id).first()
    if not todo:
        return jsonify({"message": "not todos"})
    db.session.delete(todo)
    db.session.commit()
    return jsonify({"message": "todo deleted"})


if __name__ == '__main__':
    app.run(debug=True)
