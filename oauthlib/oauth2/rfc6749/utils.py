# -*- coding: utf-8 -*-
"""
oauthlib.utils
~~~~~~~~~~~~~~

This module contains utility methods used by various parts of the OAuth 2 spec.
"""
from __future__ import absolute_import, unicode_literals

import os
import datetime
try:
    from urllib import quote
except ImportError:
    from urllib.parse import quote
try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse
from oauthlib.common import unicode_type, urldecode


def list_to_scope(scope):
    """Convert a list of scopes to a space separated string."""
    if isinstance(scope, unicode_type) or scope is None:
        return scope
    elif isinstance(scope, list):
        return " ".join([unicode_type(s) for s in scope])
    else:
        raise ValueError("Invalid scope, must be string or list.")


def scope_to_list(scope):
    """Convert a space separated string to a list of scopes."""
    if isinstance(scope, list):
        return [unicode_type(s) for s in scope]
    elif scope is None:
        return None
    else:
        return scope.split(" ")


def params_from_uri(uri):
    params = dict(urldecode(urlparse(uri).query))
    if 'scope' in params:
        params['scope'] = scope_to_list(params['scope'])
    return params


def host_from_uri(uri):
    """Extract hostname and port from URI.

    Will use default port for HTTP and HTTPS if none is present in the URI.
    """
    default_ports = {
        'HTTP': '80',
        'HTTPS': '443',
    }

    sch, netloc, path, par, query, fra = urlparse(uri)
    if ':' in netloc:
        netloc, port = netloc.split(':', 1)
    else:
        port = default_ports.get(sch.upper())

    return netloc, port


def escape(u):
    """Escape a string in an OAuth-compatible fashion.

    TODO: verify whether this can in fact be used for OAuth 2

    """
    if not isinstance(u, unicode_type):
        raise ValueError('Only unicode objects are escapable.')
    return quote(u.encode('utf-8'), safe=b'~')


def generate_age(issue_time):
    """Generate a age parameter for MAC authentication draft 00."""
    td = datetime.datetime.now() - issue_time
    age = (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / 10**6
    return unicode_type(age)


def is_secure_transport(uri):
    """Check if the uri is over ssl."""
    if os.environ.get('DEBUG'):
        return True
    return uri.lower().startswith('https://')


class GrantTypeHandler(object):
    """This class wraps a list of handlers and related response_type's
    and returns the right handler for a certain request.
    """

    def __init__(self, response_types, default_response_type):
        default_response_type = set(default_response_type.split())
        if isinstance(response_types, dict):
            response_types = response_types.items()

        self.response_types = []
        self.default_handler = False
        for response_type, handler in response_types:
            response_type = set(response_type.split())

            if (not self.default_handler
                    and default_response_type.issubset(response_type)):
                self.default_handler = handler

            self.response_types.append((response_type, handler))

        if not self.default_handler:
            raise ValueError('default_response_type does not correspond '
                             'to any given response_type')

        self.default_response_type = default_response_type

    def get(self, request):
        if not request.response_type:
            return self.default_handler

        desired_response_type = set(request.response_type.split())
        for response_type, handler in self.response_types:
            if desired_response_type.issubset(response_type):
                return handler

        return self.default_handler
