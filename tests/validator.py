# -*- coding: utf-8 -*-
""" Testing RequestValidator for oauthlib
"""
from oauthlib.common import UNICODE_ASCII_CHARACTER_SET
from oauthlib.oauth1 import RequestValidator

CLIENT_KEYS = [u'test_client_key',
               u'test_restricted_client_invalid_realms',
               u'test_restricted_client_no_realms']

CLIENT_SECRETS = {
    CLIENT_KEYS[0]: u"test_secret",
    CLIENT_KEYS[1]: u"test_secret",
    CLIENT_KEYS[2]: u"test_secret",
}

CLIENT_RSAS = {
    CLIENT_KEYS[0]: u'test RSA key',
    CLIENT_KEYS[1]: u'test RSA key',
    CLIENT_KEYS[2]: u"test RSA key",
}

REQUEST_TOKENS = {
    CLIENT_KEYS[0]: {
        'token': u'test request token0',
        'secret': u'test token secret',
        'realms': [u'photos', u'printers'],
        'redirect_uri': u'oob'
    },
    CLIENT_KEYS[1]: {
        'token': u'test request token1',
        'secret': u'test token secret',
        'realms': [u'foo', u'bar'],
        'redirect_uri': u'oob'
    },
}

ACCESS_TOKENS = {
    CLIENT_KEYS[0]: {
        'token': u'test_access_token0',
        'secret': u'test_secret',
        'realms': [u'photos', u'printers'],
    },
    CLIENT_KEYS[1]: {
        'token': u'test access token1',
        'secret': u'test token secret',
        'realms': [u'foo', u'bar'],
    },
    CLIENT_KEYS[2]: {
        'token': u'test access token2',
        'secret': u'test token secret',
        'realms': [],
    },
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
        return set(self.get_realms(token, request)).issuperset(set(realms))

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

    def get_realms(self, token, request):
        """ Get allowed realms for given access token
        Needed by: AuthorizationEndpoint, AccessTokenEndpoint
        """
        access_tokens = [token_dict for token_dict in ACCESS_TOKENS.values()
                         if token_dict['token'] == token]
        try:
            realms = access_tokens.pop()['realms']
        except IndexError:
            realms = []
        return realms

    def get_redirect_uri(self, token, request):
        """ Needed by: RequestTokenUri
        """
        return token['redirect_uri']

    def invalidate_request_token(self, client_key, request_token, request):
        """ Needed by: AccessTokenEndpoint
        """
        # do not care
        pass

    def verify_realms(self, token, realms, request):
        """ Needed by: AuthorizationEndpoint
        """
        valid_realms = self.get_realms(token)
        return set(valid_realms) == set(realms)

    def verify_request_token(self, token, request):
        """ Needed by: AuthorizationEndpoint
        """
        all_tokens = [value['token'] for value in REQUEST_TOKENS.values()]
        return token in all_tokens

    def get_default_realms(self, client_key, request):
        """ Needed by: RequestTokenEndpoint
        """
        return []
