"""
Relevant fragments from https://github.com/jpf/okta-oidc-beta

Used to handle the id_token returned by the SPA authentication process defined here@
https://github.com/okta/okta-signin-widget
"""
import urlparse
import requests
from jose import jws
from jose import jwt

default_allowed_domains = ['okta.com', 'oktapreview.com']
public_keys_cache = {}


class OktaOIDC:
    """Encapsulate an Okta OpenID Connect configuration."""

    def __init__(self, base_url=None, api_token=None, client_id=None, allowed_domains=[]):
        self.base_url = base_url
        self.api_token = api_token
        self.client_id = client_id
        if allowed_domains:
            self.allowed_domains = allowed_domains
        else:
            self.allowed_domains = default_allowed_domains

        if not self.base_url:
            raise ValueError("Okta base_url required")
        if not self.api_token:
            raise ValueError("Okta api_token required")
        if not self.client_id:
            raise ValueError("Okta client_id required")

    @staticmethod
    def domain_name_for(url):
        second_to_last_element = -2
        domain_parts = url.netloc.split('.')
        (sld, tld) = domain_parts[second_to_last_element:]
        return sld + '.' + tld

    def fetch_jwt_public_key_for(self, id_token=None):
        if id_token is None:
            raise NameError('id_token is required')

        dirty_header = jws.get_unverified_header(id_token)
        cleaned_key_id = None
        if 'kid' in dirty_header:
            dirty_key_id = dirty_header['kid']
            cleaned_key_id = dirty_key_id
        else:
            raise ValueError('The id_token header must contain a "kid"')
        if cleaned_key_id in public_keys_cache:
            return public_keys_cache[cleaned_key_id]

        unverified_claims = jwt.get_unverified_claims(id_token)
        dirty_url = urlparse.urlparse(unverified_claims['iss'])
        if OktaOIDC.domain_name_for(dirty_url) not in self.allowed_domains:
            raise ValueError('The domain in the issuer claim is not allowed')

        cleaned_issuer = dirty_url.geturl()
        oidc_discovery_url = "{}/.well-known/openid-configuration".format(
            cleaned_issuer)
        r = requests.get(oidc_discovery_url)
        openid_configuration = r.json()
        jwks_uri = openid_configuration['jwks_uri']
        r = requests.get(jwks_uri)
        jwks = r.json()
        for key in jwks['keys']:
            jwk_id = key['kid']
            public_keys_cache[jwk_id] = key

        if cleaned_key_id in public_keys_cache:
            return public_keys_cache[cleaned_key_id]
        else:
            raise RuntimeError("Unable to fetch public key from jwks_uri")

    def parse_jwt(self, id_token):
        public_key = self.fetch_jwt_public_key_for(id_token)
        rv = jwt.decode(
            id_token,
            public_key,
            algorithms='RS256',
            issuer=self.base_url,
            audience=self.client_id)
        return rv




