# NYT PyIAP
Validating JWT tokens from the Google Identity-Aware Proxy as middleware.

## Install
```
pip install -e git+git@github.com:newsdev/nyt-pyiap.git
```

## Usage
### Django
### Add to settings
Update your `settings.py` file to add the Django middleware.

```
MIDDLEWARE_CLASSES = [
  ...
  'pyiap.django.VerifyJWTMiddleware',
  ...
]
```

The `request` object in `views.py` will have two new attributes added:
* `request.jwt_user_id`: The Gooogle internal ID of the user who has been verified by IAP.
* `request.jwt_user_email`: The email address and email type of the user who has been verified by IAP.

### Flask
TBD, but will be very similar to Django.

## Contributing
TBD.
