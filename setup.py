# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
import os

PACKAGES = find_packages(exclude='tests')
README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()


def strip_comments(l):
    return l.split('#', 1)[0].strip()


def reqs(*f):
    return list(filter(None, [strip_comments(l) for l in open(
        os.path.join(os.getcwd(), *f)).readlines()]))


def get_version(version_tuple):
    if not isinstance(version_tuple[-1], int):
        return '.'.join(map(str, version_tuple[:-1])) + version_tuple[-1]
    return '.'.join(map(str, version_tuple))


init = os.path.join(
    os.path.dirname(__file__),
    'talons', 'auth', 'oauth', '__init__.py'
)

version_line = list(filter(lambda l: l.startswith('VERSION'), open(init)))[0]

VERSION = get_version(eval(version_line.split('=')[-1]))
INSTALL_REQUIRES = reqs('requirements.txt')

setup(
    name='talons.auth.oauth',
    version=VERSION,
    author='Michał Jaworski',
    author_email='swistakm@gmail.com',
    description='OAuth 1.0 extension for Talons WSGI middleware library',
    long_description=README,

    packages=PACKAGES,

    include_package_data=True,
    install_requires=INSTALL_REQUIRES,
    zip_safe=True,

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
    ],
)
