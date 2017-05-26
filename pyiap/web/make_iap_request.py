import google.auth
import google.auth.app_engine
import google.auth.compute_engine.credentials
import google.auth.iam
from google.auth.transport.requests import Request
import google.oauth2.credentials
import google.oauth2.service_account
from google.oauth2 import service_account
import requests
import requests_toolbelt.adapters.appengine
from six.moves import urllib_parse as urlparse


GCP_SECRETS = os.environ.get('GCP_SERVICE_WORKER_CREDS', '/tmp/gcp-service-worker-creds.json')
IAM_SCOPE = os.environ.get('GCP_IAM_SCOPE', 'https://www.googleapis.com/auth/iam')
OAUTH_TOKEN_URI = os.environ.get('GCP_OAUTH_TOKEN_URI', 'https://www.googleapis.com/oauth2/v4/token')


def iap_request(url, data=None, headers=None):
    if "localhost.newsdev.net" in url:
        resp = requests.post(url, headers=headers, data=data)

    else:
        base_url = urlparse.urlunparse(
            urlparse.urlparse(url)._replace(path='', query='', fragment=''))

        credentials = service_account.Credentials.from_service_account_file(GCP_SECRETS)
        bootstrap_credentials = credentials.with_scopes([IAM_SCOPE])

        if isinstance(bootstrap_credentials, google.oauth2.credentials.Credentials):
            raise Exception('make_iap_request is only supported for service accounts.')

        bootstrap_credentials.refresh(Request())

        signer_email = bootstrap_credentials.service_account_email

        if isinstance(bootstrap_credentials, google.auth.compute_engine.credentials.Credentials):
            signer = google.auth.iam.Signer(Request(), bootstrap_credentials, signer_email)
        else:
            signer = bootstrap_credentials.signer

        service_account_credentials = google.oauth2.service_account.Credentials(
            signer, signer_email, token_uri=OAUTH_TOKEN_URI, additional_claims={
                'target_audience': base_url
            })

        google_open_id_connect_token = get_google_open_id_connect_token(service_account_credentials)

        # Append our header to a list of possible headers.
        if not headers:
            headers = {'Authorization': 'Bearer {}'.format(google_open_id_connect_token)}
        else:
            headers['Authorization'] = 'Bearer {}'.format(google_open_id_connect_token)

        resp = requests.post(url, headers=headers, data=data)

        if resp.status_code == 403:
            raise Exception('Service account {} does not have permission to '
                            'access the IAP-protected application.'.format(
                                signer_email))

    if resp.status_code != 200:
        return resp.text

    return resp.text

def get_google_open_id_connect_token(service_account_credentials):
    service_account_jwt = (service_account_credentials._make_authorization_grant_assertion())
    request = google.auth.transport.requests.Request()
    body = {
        'assertion': service_account_jwt,
        'grant_type': google.oauth2._client._JWT_GRANT_TYPE,
    }
    token_response = google.oauth2._client._token_endpoint_request(request, OAUTH_TOKEN_URI, body)
    return token_response['id_token']
