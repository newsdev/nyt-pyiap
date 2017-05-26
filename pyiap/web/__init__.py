GCP_SECRETS = os.environ.get('GCP_SERVICE_WORKER_CREDS', '/tmp/gcp-service-worker-creds.json')
IAM_SCOPE = os.environ.get('GCP_IAM_SCOPE', 'https://www.googleapis.com/auth/iam')
OAUTH_TOKEN_URI = os.environ.get('GCP_OAUTH_TOKEN_URI', 'https://www.googleapis.com/oauth2/v4/token')

from pyiap.web.make_iap_request import iap_request
