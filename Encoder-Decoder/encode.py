import json
import hmac
from hashlib import sha256
from base64 import urlsafe_b64encode

segmentos = []
SECRET_KEY = 'p1t0n-c4p0'

""" HEADER """
header_dict = {
	'typ': 'JWT',
	'alg': 'HS256'
}

header_json = json.dumps(header_dict)

header = urlsafe_b64encode(header_json)
segmentos.append(header)


""" PAYLOAD """
payload_dict = {
	'user_id': 1
}

payload_json = json.dumps(payload_dict)

payload = urlsafe_b64encode(payload_json).rstrip('=')
segmentos.append(payload)


""" SIGNATURE """
signing_input = '.'.join(segmentos)

sig = hmac.new(SECRET_KEY, signing_input, sha256)

signature = urlsafe_b64encode(sig.digest()).rstrip('=')
segmentos.append(signature)


token = '.'.join(segmentos)
print token