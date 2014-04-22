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


def make_grant_hash(grant, alg):
    bits = re.search(r'[HRE]S(?P<bits>\d+)$', alg).groupdict()['bits']
    h = getattr(hashlib, 'sha%s' % bits)(grant).digest()
    return to_base64url(h[:len(h)/2])


def id_token_modifier(token, request, request_validator, expires_in):
    if 'openid' not in request.scopes:
        return token

    payload = request_validator.initial_id_token_payload(request)
    alg, private_key = request_validator.id_token_signing_method(request)

    iat = datetime.utcnow()
    exp = iat + timedelta(seconds=expires_in)
    payload.update({
        'iat': iat,
        'exp': exp,
    })

    if at_hash_required(request):
        payload['at_hash'] = make_grant_hash(token['access_token'], alg)

    if 'code' in request.response_type.split():
        payload['c_hash'] = make_grant_hash(token['code'], alg)

    id_token = jwt.sign(payload, private_key, alg=alg)
    id_token = common.to_unicode(id_token, 'UTF-8')

    token['id_token'] = id_token
    return token


def required_hashes(request):
    response_type = set(request.response_type.split())
    _hashes = []

    if response_type.issubset({'code', 'token', 'id_token'}):
        if 'token' in response_type:
            _hashes.append('at_hash')
        if 'code' in response_type:
            _hashes.append('c_hash')

    return _hashes


#TODO testar isso
#TODO tem que ajustar a criação de at_hash e c_hash
#TODO ajustar grant_types auth e implicit para os casos extras de OIDC
#TODO ajustar validator para os novos métodos, instruir para salvar OIDC!
#    KINDA done
#TODO ajustar OpenIDConnectServer para isso tudo
