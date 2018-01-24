import os

from flask import abort
from werkzeug.wrappers import Request

from pyiap.utils import validate_iap_jwt


class VerifyJWTMiddleware(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):

        # I think this is right but I am insane.
        request = Request(environ, shallow=True)

        environ['jwt_user_id'] = None
        environ['jwt_user_email'] = None
        environ['jwt_error_str'] = None

        jwt_token = request.environ.get('HTTP_X_GOOG_IAP_JWT_ASSERTION', None)
        audience = os.environ.get("GOOGLE_AUDIENCE_ID", None)

        if audience and jwt_token:

            response = validate_iap_jwt(audience, jwt_token)

            environ['jwt_user_id'] = response.get('jwt_user_id', None)
            environ['jwt_user_email'] = response.get('jwt_user_email', 'none@none.none')

            if response['error'] == True:
                payload = "<h1>Error</h1>"
                payload += "<h5>%s</h5>" % str(response.get('jwt_error_str', 'No error string.'))
                payload += "Audience: %s<br/>Token: %s<br/>" % (audience, jwt_token)
                payload += "<br/>".join(["%s: %s" % (key,value) for key,value in response.items()])
                payload += "<br/>".join(["%s: %s" % (key,value) for key,value in request.environ.items()])
                abort(500)

        return self.app(environ, start_response)
