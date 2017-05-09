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
