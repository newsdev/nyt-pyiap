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

        host = "https://%s" % request.environ.get('HTTP_HOST', None)
        jwt_token = request.environ.get('HTTP_X_GOOG_AUTHENTICATED_USER_JWT', None)

        if host and jwt_token:

            response = validate_iap_jwt(host, jwt_token)

            environ['jwt_user_id'] = response.get('jwt_user_id', None)
            environ['jwt_user_email'] = response.get('jwt_user_email', 'none@none.none')

        return self.app(environ, start_response)
