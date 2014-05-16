# -*- coding: utf-8 -*-
""" Testing RequestValidator for oauthlib
"""
from oauthlib.common import UNICODE_ASCII_CHARACTER_SET
from oauthlib.oauth1 import RequestValidator

CLIENT_KEYS = [u'test_client_key']

CLIENT_SECRETS = {
    CLIENT_KEYS[0]: u"test_secret"
}

CLIENT_RSAS = {
    CLIENT_KEYS[0]: u'test RSA key'
}

REQUEST_TOKENS = {
    CLIENT_KEYS[0]: {
        'token': u'test request token',
        'secret': u'test token secret'
    }
}

ACCESS_TOKENS = {
    CLIENT_KEYS[0]: {
        'token': u'test_access_token',
        'secret': u'test_secret',
    }
}
NONCES = []
VERIFIERS = {
    REQUEST_TOKENS[CLIENT_KEYS[0]]['token']: 'test verifier'
}


class ExampleRequestValidator(RequestValidator):
    dummy_client = 'dummy'
    dummy_request_token = 'dummy'
    dummy_access_token = 'dummy'

    default_lengths = (1, 100)

    client_key_length = default_lengths
    request_token_length = default_lengths
    access_token_length = default_lengths
    nonce_length = default_lengths
    verifier_length = default_lengths
    safe_characters = set(UNICODE_ASCII_CHARACTER_SET + '_')

    def validate_client_key(self, client_key, request):
        """ Needed by: AccessTokenEndpoint, RequestTokenEndpoint,
                       ResourceEndpoint
        """
        return client_key in CLIENT_KEYS

    def validate_request_token(self, client_key, token, request):
        """ Needed by: AccessTokenEndpoint
        """
        try:
            return REQUEST_TOKENS[client_key]['token'] == token
        except KeyError:
            return False

    def validate_access_token(self, client_key, token, request):
        """ Needed by: ResourceEndpoint
        """
        try:
            return ACCESS_TOKENS[client_key]['token'] == token
        except KeyError:
            return False

    def validate_timestamp_and_nonce(self, client_key, timestamp, nonce,
                                     request, request_token=None,
                                     access_token=None):
        """ Needed by: AccessTokenEndpoint, RequestTokenEndpoint
                       ResourceEndpoint
        """
        return ((client_key, timestamp, nonce, request_token or access_token)
                not in NONCES)

    def validate_redirect_uri(self, client_key, redirect_uri, request):
        """ Needed by: RequestTokenEndpoint
        """
        # we do not care since it's for purpose of tests
        return True

    def validate_requested_realms(self, client_key, realms, request):
        """ Needed by: RequestTokenEndpoint
        """
        # we do not care since it's for purpose of tests
        return True

    def validate_realms(self, client_key, token, request, uri=None,
                        realms=None):
        """ Needed by: ResourceEndpoint
        """
        return True

    def validate_verifier(self, client_key, token, verifier, request):
        """ Needed by: AccessTokenEndpoint
        """
        try:
            return VERIFIERS[token] == verifier
        except KeyError:
            return False

    def get_client_secret(self, client_key, request):
        """ Needed by: AccessTokenEndpoint, RequestTokenEndpoint,
                       ResourceEndpoint
        """
        return CLIENT_SECRETS.get(client_key, 'dummy')

    def get_request_token_secret(self, client_key, token, request):
        """ Needed by: AccessTokenEndpoint
        """
        return REQUEST_TOKENS.get(client_key, {'secret': 'dummy'})['secret']

    def get_access_token_secret(self, client_key, token, request):
        """ Needed by: AccessTokenEndpoint"""
        return ACCESS_TOKENS.get(client_key, {'secret': 'dummy'})['secret']

    def get_rsa_key(self, client_key, request):
        """ Needed by: AccessTokenEndpoint, RequestTokenEndpoint,
                       ResourceEndpoint
        """
        return CLIENT_RSAS.get(client_key, "dummy")

    def save_request_token(self, token, request):
        """ Needed by: RequestTokenEndpoint
        """

        REQUEST_TOKENS[request.client_key] = {
            'token': token['oauth_token'],
            'secret': token['oauth_secret'],
        }

    def save_verifier(self, token, verifier, request):
        """ Needed by: AuthorizationEndpoint
        """
        VERIFIERS[token] = verifier

    def save_access_token(self, token, request):
        """ Needed by: AccessTokenEndpoint
        """
        ACCESS_TOKENS[request.client_key] = {
            'token': token['oauth_token'],
            'secret': token['oauth_secret'],
        }
