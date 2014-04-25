import mock
import jwt
from ...unittest import TestCase

from oauthlib.oauth2 .rfc6749 import id_token


class IdTokenTest(TestCase):
    def setUp(self):
        self.mock_validator = mock.MagicMock()
        self.mock_validator.id_token_signing_key.return_value = ('HS256', 'FOOBAR')
        self.mock_validator.initial_id_token_payload.return_value = {
            'sub': 'foo',
            'iss': 'http://example.it',
            'aud': 'http://other_example.it'
        }
        self.mock_request = mock.MagicMock()
        self.mock_request.scopes = 'openid foo bar baz'
        self.mock_request.response_type = 'code'

    def test_return_token_unmodified_if_not_oidc(self):
        token = {'dummy': True}
        mock_request = mock.MagicMock()
        mock_request.scopes = 'not oidc'

        token_returned = id_token.id_token_modifier(token, mock_request,
                self.mock_validator, 1800)

        self.assertEqual(token_returned, token)

    @mock.patch('jwt.encode')
    def test_id_token_creation(self, mock_encode):
        mock_encode.return_value = 'this is an id_token'
        token = {'dummy': True}

        token_returned = id_token.id_token_modifier(token, self.mock_request,
                self.mock_validator, 1800)
        self.assertEqual(token_returned['id_token'], 'this is an id_token')

    def test_id_token_with_at_hash(self):
        token = {
            'dummy': True,
            'access_token': 'abcdef'
        }
        mock_request = mock.MagicMock()
        mock_request.scopes = 'openid foo bar baz'
        mock_request.response_type = 'id_token token'

        token_returned = id_token.id_token_modifier(token, mock_request,
                self.mock_validator, 1800)

        decoded_id_token = jwt.decode(token_returned['id_token'], 'FOOBAR')
        self.assertIn('at_hash', decoded_id_token)
        self.assertEqual(decoded_id_token['at_hash'],
                         id_token.make_grant_hash('abcdef', 'HS256'))

    def test_id_token_with_c_hash(self):
        token = {
            'dummy': True,
            'access_token': 'abcdef',
            'code': '123456'
        }
        mock_request = mock.MagicMock()
        mock_request.scopes = 'openid foo bar baz'
        mock_request.response_type = 'code id_token token'

        token_returned = id_token.id_token_modifier(token, mock_request,
                self.mock_validator, 1800)

        decoded_id_token = jwt.decode(token_returned['id_token'], 'FOOBAR')
        self.assertIn('c_hash', decoded_id_token)
        self.assertEqual(decoded_id_token['c_hash'],
                         id_token.make_grant_hash('123456', 'HS256'))
