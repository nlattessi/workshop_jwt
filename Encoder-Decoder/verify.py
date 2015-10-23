import json
import hmac
from hashlib import sha256
from base64 import urlsafe_b64encode, urlsafe_b64decode
import sys


def base64url_decode(input):
    rem = len(input) % 4

    if rem > 0:
        input += b'=' * (4 - rem)

    return urlsafe_b64decode(input)


def compare_digest(val1, val2):
        """
        Returns True if the two strings are equal, False otherwise.
        The time taken is independent of the number of characters that match.
        """
        if len(val1) != len(val2):
            return False

        result = 0

        for x, y in zip(val1, val2):
            result |= ord(x) ^ ord(y)

        return result == 0


token = sys.argv[1]
secret_key = sys.argv[2]

signing_input, signature = token.rsplit('.', 1)
header, payload = signing_input.rsplit('.', 1)

print 'header len:', len(header)
print 'payload len:', len(payload)
print 'signature len:', len(signature)

header_data = base64url_decode(header)

payload_data = base64url_decode(payload)

signature_data = base64url_decode(signature)

verification_signature = hmac.new(secret_key, signing_input, sha256).digest()
if compare_digest(signature_data, verification_signature):
	print 'Es valido!'
else:
	print 'Signature verification failed'