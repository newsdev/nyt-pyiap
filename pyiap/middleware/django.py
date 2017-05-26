from pyiap import validate_iap_jwt

from django.http import HttpResponse


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
