NYT PyIAP
=========

Validating JWT tokens from the Google Identity-Aware Proxy as
middleware.

Install
-------

::

    pip install -e git+git@github.com:newsdev/nyt-pyiap.git

Usage
-----

Django
~~~~~~

Add to settings
~~~~~~~~~~~~~~~

Update your ``settings.py`` file to add the Django middleware.

::

    MIDDLEWARE_CLASSES = [
      ...
      'pyiap.django.VerifyJWTMiddleware',
      ...
    ]

The ``request`` object in ``views.py`` will have two new attributes
added:
- ``request.jwt_user_id``: The Google internal ID of the user who
has been verified by IAP.
- ``request.jwt_user_email``: The email
address and email type of the user who has been verified by IAP.

Flask
~~~~~

Update your Flask ``app.py`` to wrap your instantiated ``Flask()``
application's ``wsgi_app`` with the ``VerifyJWTMiddleware``.

::

    app = Flask(__name__)
    app.wsgi_app = VerifyJWTMiddleware(app.wsgi_app)

The ``request.environ`` object in ``app.py`` will have two new
attributes added:
- ``request.environ['jwt_user_id']``: The Google
internal ID of the user who has been verified by IAP.
- ``request.environ['jwt_user_email']``: The email address and email type
of the user who has been verified by IAP.

Contributing
------------

TBD.
