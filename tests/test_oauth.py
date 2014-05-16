# -*- coding: utf-8 -*-
import logging
import fixtures
import mock
import falcon

import oauthlib
from oauthlib.oauth1 import SIGNATURE_TYPE_AUTH_HEADER
import testtools

from talons.auth import oauth

import validator
from validator import ExampleRequestValidator

LOG_FORMAT = "[%(levelname)-7s] %(msg)s"


class TestOAuth(testtools.TestCase):
    def setUp(self):
        self.useFixture(fixtures.FakeLogger(level=logging.DEBUG,
                                            format=LOG_FORMAT))

        access_token = validator.ACCESS_TOKENS[validator.CLIENT_KEYS[0]]
        self. oauth_client = oauthlib.oauth1.Client(
            validator.CLIENT_KEYS[0],
            client_secret=validator.CLIENT_SECRETS[validator.CLIENT_KEYS[0]],
            resource_owner_key=access_token['token'],
            resource_owner_secret=access_token['secret'],
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            signature_method=oauthlib.oauth1.SIGNATURE_PLAINTEXT,
        )

        super(TestOAuth, self).setUp()

    def _signed_request(self, url, method):
        return self.oauth_client.sign(url, method)

    def test_identity_already_exists(self):
        req = mock.MagicMock()
        req.env = mock.MagicMock()
        req.env.get = mock.MagicMock()
        req.env.get.side_effect = ['something']

        i = oauth.Identifier()
        i.identify(req)

        req.env.get.assert_called_once_with('wsgi.identity')

    def test_identity_invalid(self):
        req = mock.MagicMock(spec=falcon.Request)

        type(req).stream = stream = mock.PropertyMock(return_value=None)
        type(req).method = method = mock.PropertyMock(return_value="GET")
        type(req).headers = headers = mock.PropertyMock(return_value=dict())
        type(req).url = url = mock.PropertyMock(return_value='resource_url/')
        type(req).env = env = mock.PropertyMock(return_value=dict())

        mod_cls = 'talons.auth.oauth.OAuthIdentity'
        with mock.patch(mod_cls, spec=oauth.OAuthIdentity) as i_mock:
            i = oauth.Identifier()
            i.identify(req)

            stream.assert_called_once_with()
            method.assert_called_once_with()
            headers.assert_called_once_with()
            url.assert_called_once_with()

            assert env.assert_called_once_with()
            assert not i_mock.called

    def test_identity_valid(self):
        req = mock.MagicMock(spec=falcon.Request)

        method = "GET"
        url, headers, body = \
            self.oauth_client.sign('https://example.com/resource', method)

        type(req).stream = stream = mock.PropertyMock(return_value=None)
        type(req).method = method = mock.PropertyMock(return_value=method)
        type(req).headers = headers = mock.PropertyMock(return_value=headers)
        type(req).url = url = mock.PropertyMock(return_value=url)
        
        type(req).env = env = mock.PropertyMock(return_value=dict())

        mod_cls = 'talons.auth.oauth.OAuthIdentity'
        with mock.patch(mod_cls, spec=oauth.OAuthIdentity) as i_mock:
            i = oauth.Identifier()
            i.identify(req)

            stream.assert_called_once_with()
            method.assert_called_once_with()
            headers.assert_called_once_with()
            url.assert_called_once_with()

            assert env.called

    def test_authenticator_invalid(self):
        stream = "example body"
        method = "GET"
        headers = {}
        url = "resource"

        identity = oauth.OAuthIdentity(
            url, method=method, headers=headers, stream=stream)

        authenticator = oauth.Authenticator(oauth_validator=ExampleRequestValidator())
        assert not authenticator.authenticate(identity)

    def test_authenticator_valid(self):
        method = "GET"

        url, headers, body = \
            self.oauth_client.sign('https://example.com/resource', method)

        identity = oauth.OAuthIdentity(
            url, method=method, headers=headers, stream=body
        )

        authenticator = oauth.Authenticator(oauth_validator=ExampleRequestValidator())
        assert authenticator.authenticate(identity)