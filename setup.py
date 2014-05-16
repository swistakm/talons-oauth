# -*- coding: utf-8 -*-
from setuptools import setup, find_packages
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src'))
from talons.auth.oauth import __version__ as version

PACKAGES = find_packages(exclude='tests')
README = open(os.path.join(os.path.dirname(__file__), 'README.md')).read()


def strip_comments(l):
    return l.split('#', 1)[0].strip()


def reqs(*f):
    return list(filter(None, [strip_comments(l) for l in open(
        os.path.join(os.getcwd(), *f)).readlines()]))


install_requires = reqs('requirements.txt')
setup(
    name='talons.auth.oauth',
    version=version,
    author='Michał Jaworski',
    author_email='swistakm@gmail.com',
    description='OAuth 1.0 extension for Talons WSGI middleware library',
    long_description=README,

    packages=PACKAGES,

    include_package_data=True,
    install_requires=install_requires,
    zip_safe=True,

    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
)