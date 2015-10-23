from flask import Flask
from flask import request
from flask import jsonify
from flask import render_template
from flask import g
from flask import make_response
import json
import requests
from hashids import Hashids
from datetime import datetime, timedelta
import jwt
from jwt import DecodeError, ExpiredSignature
from functools import wraps


API = 'http://api.ventas-privadas.com'
API_V2 = 'http://api-v2.ventas-privadas.com'
SECRET_KEY = 'p1t0n-c4p0'


app = Flask(__name__)


def create_token(user, admin=False):
	payload = {
		# subject
		'sub': user,
		# issued at
		'iat': datetime.utcnow(),
		# expiry
		'exp': datetime.utcnow() + timedelta(days=1),
		# private claim
		'admin': admin
	}

	token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
	return token.decode('unicode_escape')

def parse_token(req):
	token = req.headers.get('Authorization')
	return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])

def login_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if not request.headers.get('Authorization'):
			response = jsonify(message='Missing authorization header')
			response.status_code = 401
			return response

		try:
			payload = parse_token(request)
		except DecodeError:
			response = jsonify(message='Token is invalid')
			response.status_code = 401
			return response
		except ExpiredSignature:
			response = jsonify(message='Token has expired')
			response.status_code = 401
			return response

		g.user = payload['sub']
		g.admin = payload['admin']

		return f(*args, **kwargs)

	return decorated_function


@app.route('/')
def index():
	return render_template('index.html')

@app.route('/get_token', methods=['POST'])
def get_token():
	data = request.get_json(force=True)

	user = data['username']
	password = data['password']

	if user == 'user' and password == 'password':
		token = create_token(user, admin=False)
		return jsonify(token=token)
	elif user == 'admin' and password == 'admin':
		token = create_token(user, admin=True)
		return jsonify(token=token)
	else:
		response = jsonify(message='invalid username/password')
		response.status_code = 401
		return response

@app.route('/get_payload')
@login_required
def get_payload():
	payload = parse_token(request)
	return json.dumps(payload, indent=4)

@app.route('/proxy/menus')
@login_required
def proxy_menus():
	if g.admin:
		r = requests.get(API_V2 + '/menus')
		return json.dumps(r.json(), indent=4)
	else:
		response = jsonify(message='No tenes acceso')
		response.status_code = 401
		return response


@app.route('/proxy/user/<int:id>', methods=['GET'])
@login_required
def proxy_user(id):
	hashidsLib = Hashids(salt='i&gz82r~W06,ELz0B?&:bS%R|BNJ?Hg}', min_length=10)
	hashid = hashidsLib.encode(id)
	
	r = requests.get(API + '/users/' + hashid)
	
	return json.dumps(r.json(), indent=4)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
