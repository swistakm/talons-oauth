# -*- coding: utf-8 -*-
import logging

import falcon
import fixtures
import mock
import oauthlib
from oauthlib.oauth1 import SIGNATURE_TYPE_AUTH_HEADER
import testtools
from talons.auth.oauth.oauth1 import Authenticator, OAuthIdentity, Identifier

from .validator import ExampleRequestValidator
from . import validator

LOG_FORMAT = "[%(levelname)-7s] %(msg)s"


class TestOAuth(testtools.TestCase):
    def setUp(self):
        self.useFixture(fixtures.FakeLogger(level=logging.DEBUG,
                                            format=LOG_FORMAT))
        super(TestOAuth, self).setUp()

    def get_oauth_client(self, client_key):
        access_token = validator.ACCESS_TOKENS[client_key]
        return oauthlib.oauth1.Client(
            client_key,
            client_secret=validator.CLIENT_SECRETS[client_key],
            resource_owner_key=access_token['token'],
            resource_owner_secret=access_token['secret'],
            signature_type=SIGNATURE_TYPE_AUTH_HEADER,
            signature_method=oauthlib.oauth1.SIGNATURE_PLAINTEXT,
        )

    def _signed_request(self, url, method):
        return self.oauth_client.sign(url, method)

    def test_identity_already_exists(self):
        req = mock.MagicMock()
        req.env = mock.MagicMock()
        req.env.get = mock.MagicMock()
        req.env.get.side_effect = ['something']

        i = Identifier()
        i.identify(req)

        req.env.get.assert_called_once_with('wsgi.identity')

    def test_identity_invalid(self):
        req = mock.MagicMock(spec=falcon.Request)

        type(req).stream = stream = mock.PropertyMock(return_value=None)
        type(req).headers = headers = mock.PropertyMock(return_value=dict())
        type(req).query_string = query = mock.PropertyMock(return_value="")

        type(req).method = mock.PropertyMock(return_value="GET")
        type(req).url = mock.PropertyMock(return_value='resource_url/')

        type(req).env = env = mock.PropertyMock(return_value=dict())

        mod_cls = 'talons.auth.oauth.oauth1.OAuthIdentity'
        with mock.patch(mod_cls, spec=OAuthIdentity) as i_mock:
            i = Identifier()
            i.identify(req)

            # this three must me used to check if it could be OAuth
            stream.assert_called_once_with()
            headers.assert_called_once_with()
            query.assert_called_once_with()

            assert env.called
            assert not i_mock.called

    def test_identity_valid(self):
        req = mock.MagicMock(spec=falcon.Request)

        method = "GET"
        url, headers, body = \
            self.get_oauth_client(validator.CLIENT_KEYS[0]).sign(
                'https://example.com/resource', method)

        type(req).stream = stream = mock.PropertyMock(return_value=None)
        type(req).method = method = mock.PropertyMock(return_value=method)
        type(req).headers = headers = mock.PropertyMock(return_value=headers)

        type(req).query_string = mock.PropertyMock(return_value="")
        type(req).url = url = mock.PropertyMock(return_value=url)

        # clean env to ensure that won't stop checking for identity
        type(req).env = mock.PropertyMock(return_value=dict())

        mod_cls = 'talons.auth.oauth.oauth1.OAuthIdentity'
        with mock.patch(mod_cls, spec=OAuthIdentity):
            i = Identifier()
            i.identify(req)

            assert stream.called
            assert method.called
            assert headers.called
            assert url.called
            assert req.env[Identifier.IDENTITY_ENV_KEY]

    def test_authenticator_invalid(self):
        """ Test authentication fail when request does not identify
        """
        stream = "example body"
        method = "GET"
        headers = {}
        url = "resource"

        identity = OAuthIdentity(
            url, method=method, headers=headers, stream=stream)

        authenticator = Authenticator(
            oauth_validator=ExampleRequestValidator())
        assert not authenticator.authenticate(identity)

    def test_authenticator_valid_realms_match(self):
        """ Test authentication success when realms and token are valid
        """
        method = "GET"

        # CLIENT_KEYS[0] is a consumer with 'photos', 'printers' realms
        url, headers, body = \
            self.get_oauth_client(validator.CLIENT_KEYS[0]).sign(
                'https://example.com/resource', method)

        identity = OAuthIdentity(
            url, method=method, headers=headers, stream=body
        )

        authenticator = Authenticator(
            oauth_validator=ExampleRequestValidator(),
            realms=['photos', 'printers'])
        assert authenticator.authenticate(identity)

    def test_authenticator_invalid_realm(self):
        """ Test authentication fail when access token is valid but
        it has no required realms
        """
        method = "GET"
        # CLIENT_KEYS[1] is a consumer with 'foo', 'bar' realms
        url, headers, body = \
            self.get_oauth_client(validator.CLIENT_KEYS[1]).sign(
                'https://example.com/resource', method)

        identity = OAuthIdentity(
            url, method=method, headers=headers, stream=body,
        )

        authenticator = Authenticator(
            oauth_validator=ExampleRequestValidator(),
            realms=['photos', 'printers'],
        )
        assert not authenticator.authenticate(identity)

    def test_authenticator_no_realms(self):
        """ Test authentication fail when consumer has access token without
        any realms
        """
        method = "GET"

        # CLIENT_KEYS[2] is a consumer with no realms
        url, headers, body = \
            self.get_oauth_client(validator.CLIENT_KEYS[2]).sign(
                'https://example.com/resource', method)

        identity = OAuthIdentity(
            url, method=method, headers=headers, stream=body,
        )

        authenticator = Authenticator(
            oauth_validator=ExampleRequestValidator(),
            realms=['photos', 'printers'],
        )
        assert not authenticator.authenticate(identity)

    def test_authenticator_valid_no_realms_required(self):
        """ Test authentication success when realms are not required
        """
        method = "GET"

        # CLIENT_KEYS[0] is a consumer with 'photos', 'printers' realms
        url, headers, body = \
            self.get_oauth_client(validator.CLIENT_KEYS[0]).sign(
                'https://example.com/resource', method)

        identity = OAuthIdentity(
            url, method=method, headers=headers, stream=body
        )

        authenticator = Authenticator(
            oauth_validator=ExampleRequestValidator(),
            realms=[])
        assert authenticator.authenticate(identity)
