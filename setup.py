import os.path
from pip.download import PipSession
from pip.req import parse_requirements

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


setup(
    name='nyt-pyiap',
    version='0.0.5',
    author='Jeremy Bowers',
    author_email='jeremy.bowers@nytimes.com',
    url='https://github.com/newsdev/nyt-pyiap',
    description='Python utility functions and Django/Flask middlewares for validating JWT tokens from Google\'s Identity-Aware Proxy',
    long_description=read('README.rst'),
    packages=('pyiap',),
    entry_points={},
    license="Apache License 2.0",
    keywords='google identity-aware proxy iap jwt',
    install_requires=['pyjwt', 'requests'],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
    ]
)
