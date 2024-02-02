import json, jwt
from flask import Blueprint, request, jsonify, current_app, Response
from flask_restful import Api, Resource
from datetime import datetime
from auth_middleware import token_required
from model.users import User
user_api = Blueprint('user_api', __name__, url_prefix='/api/users')
api = Api(user_api)
class UserAPI:
    class _CRUD(Resource):
        @token_required
        def post(self, current_user):
            ''' Create a new user '''
            body = request.get_json()
            name = body.get('name')
            if name is None or len(name) < 2:
                return {'message': f'Name is missing or less than 2 characters'}, 400
            uid = body.get('uid')
            if uid is None or len(uid) < 2:
                return {'message': f'User ID is missing or less than 2 characters'}, 400
            password = body.get('password')
            dob = body.get('dob')
            age = body.get('age')  # New: Extract age
            ''' Setup User Object '''
            uo = User(name=name, uid=uid, age=age)  # Include age when creating user object
            if password is not None:
                uo.set_password(password)
            if dob is not None:
                try:
                    uo.dob = datetime.strptime(dob, '%Y-%m-%d').date()
                except:
                    return {'message': f'Invalid date of birth format: {dob}, must be mm-dd-yyyy'}, 400
            ''' Add User to Database '''
            user = uo.create()
            if user:
                return jsonify(user.read())
            else:
                return {'message': f'Error processing {name}. Either a format error occurred or User ID {uid} is duplicate'}, 400
        @token_required
        def get(self, current_user):
            ''' Retrieve all users '''
            users = User.query.all()
            json_ready = [user.read() for user in users]
            return jsonify(json_ready)
    class _Security(Resource):
        def post(self):
            try:
                body = request.get_json()
                if not body:
                    return {
                        "message": "Please provide user details",
                        "data": None,
                        "error": "Bad request"
                    }, 400
                uid = body.get('uid')
                if uid is None:
                    return {'message': f'User ID is missing'}, 400
                password = body.get('password')
                user = User.query.filter_by(_uid=uid).first()
                if user is None or not user.is_password(password):
                    return {'message': f"Invalid user ID or password"}, 400
                if user:
                    try:
                        token = jwt.encode(
                            {"_uid": user._uid},
                            current_app.config["SECRET_KEY"],
                            algorithm="HS256"
                        )
                        resp = Response("Authentication for %s successful" % (user._uid))
                        resp.set_cookie("jwt", token,
                                max_age=3600,
                                secure=True,
                                httponly=True,
                                path='/',
                                samesite='None'
                                )
                        return resp
                    except Exception as e:
                        return {
                            "error": "Something went wrong",
                            "message": str(e)
                        }, 500
                return {
                    "message": "Error fetching auth token!",
                    "data": None,
                    "error": "Unauthorized"
                }, 404
            except Exception as e:
                return {
                        "message": "Something went wrong!",
                        "error": str(e),
                        "data": None
                }, 500
    api.add_resource(_CRUD, '/')
    api.add_resource(_Security, '/authenticate')