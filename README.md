[![Build Status](https://travis-ci.org/swistakm/talons-oauth.svg?branch=master)](https://travis-ci.org/swistakm/talons-oauth)

# Talons OAuth authentication extension

`talons-oauth` provides OAuth 1.0 extension for
[Talons WSGI middleware library](https://github.com/talons/talons)
in `talons.auth` namespace. You can install it with pip:

```
pip install talons-oauth
```


## Usage example

Use `talons-oauth` the same way you would use any other talons auth middleware

```python
import falcon
from falcon.auth.oauth import oauth1

# Assume getappconfig() returns a dictionary of application configuration
# options that may have been read from some INI file...
config = getappconfig()

auth_middleware = middleware.create_middleware(identify_with=[oauth1.Identifier],
                                               authenticate_with=[oauth1.Authenticator],
                                               **config)
app = falcon.API()
```

## `talons.auth.oauth.oauth1.Identifier`

OAuth authentication flow is a bit more sophisticated than `talons.auth`
middlewares assumes about typical authentication. There is no clear boundary
between identification and authentication in most of OAuth implementations.
There is no user credentials *per se* but credentials of oauth consumer
that authenticates on behalf of user. Because of that `oauth1.Identifier`
identificates "user" by whole set of request body, method, headers and url
parameters. This data will be needed then for verifing request signature.

`oauth1.Identifier.identify()` returns `True` only if request looks like
OAuth 1.0. request - has either valid auth header, body parameters or query
string (as specified in [RFC 5849](http://tools.ietf.org/html/rfc5849)).
Identity stored in request is a `talons.auth.oauth.oauth1.OAuthIdentity`
instance that subclasses `talons.auth.interfaces.Identity`. All its base
attributes (`login`, `key`, `roles`, `groups`) are set to `None' or default
value. This should not break other talons authenticators.

## `talons.auth.oauth.oauth1.Authenticator`

`oauth1.Authenticator` won't work OOTB. It uses
[oauthlib](https://github.com/idan/oauthlib) as oauth provider backend which as
well as falcon and talons do tries to be non opinionated. This means that it
doesn't assume anything about your your type of storage or data architecture.
You must provide an
`oauthlib.oauth1.rfc5849.request_validator.RequestValidator`
subclass instance that tells library how to validate/save/verify/retrieve your
tokens, nonces, keys, etc. Fortunately this procedure is very simple and well
documented in [oauthlib's documentation](https://oauthlib.readthedocs.org/en/latest/oauth1/server.html).

Other thing you would like probably to configure is a list of available
authentication realms that are required by your API instance. It can be set as
a list of required realms for whole api instance. Unfortunately
falcon hooks are not aware of resource affected by request and realms cannot
be set per resource individually. If you would like to have diffrent
authentication realms for many resources I would advice you splitting your API
into many instances based on their realms.

Full list of configuration parameters:

* `oauth1_validator`: `oauthlib.oauth1.rfc5849.request_validator.RequestValidator`
  (required). Defines how to validate/save/verify/retrieve your OAuth 1.0. tokens,
  nonces, keys, etc. For full documentation refer to
  [oauthlib's RequestValidator](https://oauthlib.readthedocs.org/en/latest/oauth1/validator.html)
  documentation.
* `oauth1_realms`: list (defaults to []). list of required realms for consumer
  access tokens.

## Providing OAuth 1.0. endpoints

Providing endpoints for accessing/authorizing request tokens and access tokens
is beyond the scope of this library. Once you create your `RequestValidator`
subclass it should be easy to use
[generic oauthlib endpoints](https://oauthlib.readthedocs.org/en/latest/oauth1/server.html#create-your-endpoint-views).