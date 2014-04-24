# -*- coding: utf-8 -*-
from .request_validator import RequestValidator


class IdTokenValidator(RequestValidator):
    def initial_id_token_payload(self, request, client):
        """Return a dict containing three basic values for an id_token:
            - iss: Should be an url identifying the issuer
            - sub: Should be an unique identifier of the client being authenticated
            - aud: Should be either an url or a list of urls of the audience

        :param request: oauthlib.common.Request
        :param client: Client object set by you, see authenticate_client

        Method is used by:
            - OpenID Connect Server
        """
        raise NotImplementedError('Subclasses must implement this method.')

    def id_token_signing_key(self, request, client):
        """Should return a tuple containing the encryption method and the
        private key to encode the id_token. Options are:
            - alg: HS256. In this case, the client_secret should be returned. Ex:

                return ('HS256', 'my private key')
            - alg: RS256. Uses a RSA private key to encode the id_token. You
            MUST return a Crypto.PublicKey.RSA object. Ex:

                from Crypto.PublicKey import RSA

                priv_key = RSA.importKey(open('path/to/pubkey', 'r').read())
                return ('RS256', priv_key)

        :param request: oauthlib.common.Request
        :param client: Client object set by you, see authenticate_client

        Method is used by:
            - OpenID Connect Server
        """
        raise NotImplementedError('Subclasses must implement this method.')
