# -*- coding: utf-8 -*-\
import logging

from oauthlib.oauth1.rfc5849 import signature
from oauthlib.oauth1 import ResourceEndpoint
from talons import exc
from talons.auth import interfaces

LOG = logging.getLogger(__name__)


class Identifier(interfaces.Identifies):
    def identify(self, request):
        if request.env.get(self.IDENTITY_ENV_KEY) is not None:
            return True

        if self._is_oauth(request):
            identity = OAuthIdentity(
                request.url,
                request.method,
                request.stream,
                request.headers,
            )
            request.env[self.IDENTITY_ENV_KEY] = identity
            return True

        return False

    @staticmethod
    def _is_oauth(request):
        check = signature.collect_parameters
        return any((
            check(headers=request.headers,
                  exclude_oauth_signature=False, with_realm=True),
            check(body=request.stream,
                  exclude_oauth_signature=False),
            check(uri_query=request.query_string,
                  exclude_oauth_signature=False)
        ))


class Authenticator(interfaces.Authenticates):
    def __init__(self, **conf):
        """ Construct a concrete object with a set of keyword configuration
        options.

        :param **conf:

            oauth_validator: RequestValidator for oauthlib

        :raises `talons.exc.BadConfiguration` if configuration options
            are not valid or conflict with each other.
        """
        oauth_validator = conf.pop('oauth_validator', None)
        if not oauth_validator:
            msg = ("Missing required oauth_validator "
                   "configuration option.")
            LOG.error(msg)
            raise exc.BadConfiguration(msg)

        self.provider = ResourceEndpoint(oauth_validator)
        self.realms = conf.pop('realms', [])

    def authenticate(self, identity):
        """ Authenticate user client using oauthlib's ResourceEndopoint
        """
        v, r = self.provider.validate_protected_resource_request(
            # we use gettattr because we depend on overriden Identity
            # - other identities can lack these attributes
            getattr(identity, 'url', None),
            http_method=getattr(identity, 'method', None),
            body=getattr(identity, 'stream', None),
            headers=getattr(identity, 'headers', None),
            realms=self.realms,
        )
        return bool(v)


class OAuthIdentity(interfaces.Identity):
    def __init__(self, url, method, stream, headers):
        self.url = url
        self.method = method
        self.stream = stream
        self.headers = headers

        super(OAuthIdentity, self).__init__(None)
