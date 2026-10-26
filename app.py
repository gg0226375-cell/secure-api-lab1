from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)

# App配置
app.config["JWT_SECRET_KEY"] = "lab-secret-key-2026-do-not-use-in-production"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

jwt = JWTManager(app)
db = SQLAlchemy(app)

# 用户ORM模型，ORM自动防护SQL注入
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    password_hash = db.Column(db.LargeBinary)

# 创建数据库，预置测试账号 admin / pass1234
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username="admin").first():
        hashed = bcrypt.hashpw(b"pass1234", bcrypt.gensalt())
        user = User(username="admin", password_hash=hashed)
        db.session.add(user)
        db.session.commit()


# 接口1 POST /auth/login 用户登录认证
@app.route("/auth/login", methods=["POST"])
def login():
    req_data = request.get_json()
    username = req_data.get("username")
    password_raw = req_data.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or not bcrypt.checkpw(password_raw.encode("utf-8"), user.password_hash):
        return jsonify({"msg": "Bad username or password"}), 401

    token = create_access_token(identity=username)
    return jsonify(access_token=token)


# 接口2 GET /api/data 需要鉴权，返回用户列表；做XSS转义
@app.route("/api/data", methods=["GET"])
@jwt_required()
def api_data():
    current_login_user = get_jwt_identity()
    result = []
    for u in User.query.all():
        safe_username = str(u.username).replace("<", "&lt;").replace(">", "&gt;")
        result.append({"id": u.id, "username": safe_username})
    return jsonify(logged_user=current_login_user, user_list=result)


# 接口3 自定义接口 GET /api/whoami 返回当前登录用户信息
@app.route("/api/whoami", methods=["GET"])
@jwt_required()
def whoami():
    user = get_jwt_identity()
    safe_user = str(user).replace("<", "&lt;").replace(">", "&gt;")
    return jsonify({"current_user": safe_user})


if __name__ == "__main__":
    app.run(debug=False)
