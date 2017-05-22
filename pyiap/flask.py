from pyiap import validate_iap_jwt

from flask import abort
from werkzeug.wrappers import Request

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
