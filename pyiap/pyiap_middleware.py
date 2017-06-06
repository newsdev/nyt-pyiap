from django.http import HttpResponse
from flask import abort
from werkzeug.wrappers import Request

import jwt
import requests

"""
Both of these functions are taken directly from the Google example here:
https://github.com/GoogleCloudPlatform/python-docs-samples/blob/master/iap/validate_jwt.py
"""

def validate_iap_jwt(base_url, iap_jwt):
    """
    Validate a JWT passed to your application by Identity-Aware Proxy.
    Args:
      base_url: The URL from the incoming request, minus any path, query, etc.
                For instance: "https://example.com:8443" or
                "https://example.appspot.com" .
      iap_jwt: The contents of the X-Goog-Authenticated-User-JWT header.
    Returns:
      (user_id, user_email, error_str).
    """
    try:
        key_id = jwt.get_unverified_header(iap_jwt).get('kid')
        if not key_id:
            return {"jwt_error_str": '** ERROR: no key ID **', "error": True}
        key = get_iap_key(key_id)
        decoded_jwt = jwt.decode(
            iap_jwt, key,
            algorithms=['ES256'],
            audience=base_url)
        return {"jwt_user_id": decoded_jwt['sub'], "jwt_user_email": decoded_jwt['email'], "error": False}
    except (jwt.exceptions.InvalidTokenError,
            requests.exceptions.RequestException) as e:
        return {"jwt_error_str": '** ERROR: JWT validation error {} **'.format(e), "error": True}


def get_iap_key(key_id):
    """
    Retrieves a public key from the list published by Identity-Aware Proxy,
    re-fetching the key file if necessary.
    """
    key_cache = get_iap_key.key_cache
    key = key_cache.get(key_id)
    if not key:
        # Re-fetch the key file.
        resp = requests.get(
            'https://www.gstatic.com/iap/verify/public_key')
        if resp.status_code != 200:
            raise Exception(
                'Unable to fetch IAP keys: {} / {} / {}'.format(
                    resp.status_code, resp.headers, resp.text))
        key_cache = resp.json()
        get_iap_key.key_cache = key_cache
        key = key_cache.get(key_id)
        if not key:
            raise Exception('Key {!r} not found'.format(key_id))
    return key

get_iap_key.key_cache = {}


class VerifyJWTMiddleware(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):

        # I think this is right but I am insane.
        request = Request(environ, shallow=True)

        environ['jwt_user_id'] = None
        environ['jwt_user_email'] = None
        environ['jwt_error_str'] = None

        print(request.__dict__)

        host = "%s://%s" % (request.environ.get('HTTP_X_FORWARDED_PROTO', None), request.environ.get('HTTP_HOST', None))
        jwt_token = request.environ.get('HTTP_X_GOOG_AUTHENTICATED_USER_JWT', None)

        if host and jwt_token:

            response = validate_iap_jwt(host, jwt_token)

            environ['jwt_user_id'] = response.get('jwt_user_id', None)
            environ['jwt_user_email'] = response.get('jwt_user_email', 'none@none.none')

            if response['error'] == True:
                payload = "<h1>Error</h1>"
                payload += "<h5>%s</h5>" % str(response.get('jwt_error_str', 'No error string.'))
                payload += "Host: %s<br/>Token: %s<br/>" % (host, jwt_token)
                payload += "<br/>".join(["%s: %s" % (key,value) for key,value in response.items()])
                payload += "<br/>".join(["%s: %s" % (key,value) for key,value in request.environ.items()])
                abort(500)

        return self.app(environ, start_response)



class VerifyJWTMiddleware(object):
    def process_request(self, request):
        """
        Adds attributes to the Django request object so that we can access
        an authenticated user in a view or some other response.
        """

        request.jwt_user_id = None
        request.jwt_user_email = None
        request.jwt_error_str = None

        # Construct the hostname from the protocol and the hostname.
        host = "%s://%s" % (request.META.get('HTTP_X_FORWARDED_PROTO', None), request.META.get('HTTP_HOST', None))
        jwt_token = request.META.get('HTTP_X_GOOG_AUTHENTICATED_USER_JWT', None)

        # Only modify the response if we're in an environment where IAP is running.
        # This isn't going to work on your local if that's what you expect.
        if host and jwt_token:

            # Run the validation step.
            response = validate_iap_jwt(host, jwt_token)

            # If there's an error, bail with a 500 and a big debug page.
            if response['error'] == True:
                payload = "<h1>Error</h1>"
                payload += "<h5>%s</h5>" % str(response.get('jwt_error_str', 'No error string.'))
                payload += "Host: %s<br/>Token: %s<br/>" % (host, jwt_token)
                payload += "<br/>".join(["%s: %s" % (key,value) for key,value in response.items()])
                payload += "<br/>".join(["%s: %s" % (key,value) for key,value in request.META.items()])
                return HttpResponse(payload, status=500)

            # Assign the ID and email to the request if they exist.
            request.jwt_user_id = response.get('jwt_user_id', None)
            request.jwt_user_email = response.get('jwt_user_email', None)
