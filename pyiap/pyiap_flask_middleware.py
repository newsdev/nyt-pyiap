import os

from flask import abort
from werkzeug.wrappers import Request

from pyiap.utils import validate_iap_jwt_from_compute_engine


class VerifyJWTMiddleware(object):
    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):

        # I think this is right but I am insane.
        request = Request(environ, shallow=True)

        environ['jwt_user_id'] = None
        environ['jwt_user_email'] = None
        environ['jwt_error_str'] = None

        cloud_project_number = os.environ.get('CLOUD_PROJECT_NUMBER', None)
        backend_service_id = os.environ.get('BACKEND_SERVICE_ID', None)
        jwt_token = request.environ.get('HTTP_X_GOOG_IAP_JWT_ASSERTION', None)

        if cloud_project_number and backend_service_id and jwt_token:

            sub, email, error  = validate_iap_jwt_from_compute_engine(jwt_token, cloud_project_number, backend_service_id)

            environ['jwt_user_id'] = sub
            environ['jwt_user_email'] = email

            if error:
                payload = "<h1>Error</h1>"
                payload += "<h5>%s</h5>" % str(error)
                payload += "Project #: %s<br/> Email: <br/>Service ID: %s<br/>Token: %s<br/>" % (cloud_project_number, backend_service_id, jwt_token)
                payload += "<br/>".join(["%s: %s" % (key,value) for key,value in request.environ.items()])
                abort(500)

        return self.app(environ, start_response)
