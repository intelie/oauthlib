# coding: utf-8 -*-
import re
import base64
import hashlib
from datetime import datetime
from datetime import timedelta
import jwt

from ... import common


def to_base64url(src):
    return base64.urlsafe_b64encode(src).replace('=', '')


def is_implicit_or_hybrid_flow(request):
    if request.response_type == 'code':
        return False

    implicit_or_hybrid_response_types = ['code', 'token', 'id_token']
    response_type = set(request.response_type.split())

    return response_type.issubset(implicit_or_hybrid_response_types)


def at_hash_required(request):
    return (is_implicit_or_hybrid_flow(request)
            and 'token' in request.response_type.split())


def c_hash_required(request):
    return (is_implicit_or_hybrid_flow(request)
            and 'code' in request.response_type.split())


def make_grant_hash(grant, alg):
    bits = re.search(r'[HRE]S(?P<bits>\d+)$', alg).groupdict()['bits']
    h = getattr(hashlib, 'sha%s' % bits)(grant).digest()
    return to_base64url(h[:len(h)/2])


def id_token_modifier(token, request, request_validator, expires_in):
    if 'openid' not in request.scopes:
        return token

    payload = request_validator.initial_id_token_payload(request, request.client)
    alg, private_key = request_validator.id_token_signing_key(request, request.client)

    iat = datetime.utcnow()
    exp = iat + timedelta(seconds=expires_in)
    payload.update({
        'iat': iat,
        'exp': exp,
    })

    if is_implicit_or_hybrid_flow(request):
        payload['nonce'] = common.generate_nonce()

    if at_hash_required(request):
        payload['at_hash'] = make_grant_hash(token['access_token'], alg)

    if c_hash_required(request):
        payload['c_hash'] = make_grant_hash(token['code'], alg)

    id_token = jwt.encode(payload, private_key, alg=alg)
    id_token = common.to_unicode(id_token, 'UTF-8')

    token['id_token'] = id_token
    return token


#TODO tem que ajustar a criação de at_hash e c_hash
#TODO ajustar grant_types auth e implicit para os casos extras de OIDC
#TODO ajustar validator para os novos métodos, instruir para salvar OIDC!
#    KINDA done
#TODO ajustar OpenIDConnectServer para isso tudo
