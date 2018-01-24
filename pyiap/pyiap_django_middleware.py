import os

from django.http import HttpResponse

from pyiap.utils import validate_iap_jwt_from_compute_engine


class VerifyJWTMiddleware(object):
    def process_request(self, request):
        """
        Adds attributes to the Django request object so that we can access
        an authenticated user in a view or some other response.
        """

        request.jwt_user_id = None
        request.jwt_user_email = None
        request.jwt_error_str = None

        jwt_token = request.META.get('HTTP_X_GOOG_IAP_JWT_ASSERTION', None)

        # Only modify the response if we're in an environment where IAP is running.
        # This isn't going to work on your local if that's what you expect.
        if jwt_token:

            # Run the validation step.
            sub, email, error = validate_iap_jwt_from_compute_engine(jwt_token)

            # If there's an error, bail with a 500 and a big debug page.
            if error:
                payload = "<h1>Error</h1>"
                payload += "<h5>%s</h5>" % str(error)
                payload += "<br/>".join(["%s: %s" % (key,value) for key,value in request.META.items()])
                return HttpResponse(payload, status=500)

            # Assign the ID and email to the request if they exist.
            request.jwt_user_id = sub
            request.jwt_user_email = email
