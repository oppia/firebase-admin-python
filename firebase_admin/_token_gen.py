# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Firebase token minting and validation sub module."""

import calendar
import datetime
import time

import cachecontrol
import requests
import six
from google.auth import credentials
from google.auth import crypt
from google.auth import iam
from google.auth import jwt
from google.auth import transport
import google.auth.exceptions
import google.oauth2.id_token
import google.oauth2.service_account

from firebase_admin import exceptions
from firebase_admin import _auth_utils


# ID token constants
ID_TOKEN_ISSUER_PREFIX = 'https://securetoken.google.com/'

# Session cookie constants
COOKIE_ISSUER_PREFIX = 'https://session.firebase.google.com/'
MIN_SESSION_COOKIE_DURATION_SECONDS = int(datetime.timedelta(minutes=5).total_seconds())
MAX_SESSION_COOKIE_DURATION_SECONDS = int(datetime.timedelta(days=14).total_seconds())

# Custom token constants
MAX_TOKEN_LIFETIME_SECONDS = int(datetime.timedelta(hours=1).total_seconds())
FIREBASE_AUDIENCE = ('https://identitytoolkit.googleapis.com/google.'
                     'identity.identitytoolkit.v1.IdentityToolkit')
RESERVED_CLAIMS = set([
    'acr', 'amr', 'at_hash', 'aud', 'auth_time', 'azp', 'cnf', 'c_hash',
    'exp', 'firebase', 'iat', 'iss', 'jti', 'nbf', 'nonce', 'sub'
])
METADATA_SERVICE_URL = ('http://metadata.google.internal/computeMetadata/v1/instance/'
                        'service-accounts/default/email')

_CLOCK_SKEW_SECS = 10


class _EmulatedSigner(crypt.Signer):

    @property
    def key_id(self):
        return b''

    def sign(self, unused_message):
        return b''


class _SigningProvider(object):
    """Stores a reference to a google.auth.crypto.Signer."""

    def __init__(self, signer, signer_email):
        self._signer = signer
        self._signer_email = signer_email

    @property
    def signer(self):
        return self._signer

    @property
    def signer_email(self):
        return self._signer_email

    @classmethod
    def from_credential(cls, google_cred):
        return _SigningProvider(google_cred.signer, google_cred.signer_email)

    @classmethod
    def from_iam(cls, request, google_cred, service_account):
        signer = iam.Signer(request, google_cred, service_account)
        return _SigningProvider(signer, service_account)

    @classmethod
    def emulated(cls):
        return _SigningProvider(_EmulatedSigner(), 'firebase-auth-emulator@example.com')


class TokenGenerator(object):
    """Generates custom tokens and session cookies."""

    def __init__(self, app, client):
        self.app = app
        self.client = client
        self.request = transport.requests.Request()
        self._signing_provider = None

    def _init_signing_provider(self):
        """Initializes a signing provider by following the go/firebase-admin-sign protocol."""
        if _auth_utils.is_emulator_enabled():
            return _SigningProvider.emulated()

        # If the SDK was initialized with a service account, use it to sign bytes.
        google_cred = self.app.credential.get_credential()
        if isinstance(google_cred, google.oauth2.service_account.Credentials):
            return _SigningProvider.from_credential(google_cred)

        # If the SDK was initialized with a service account email, use it with the IAM service
        # to sign bytes.
        service_account = self.app.options.get('serviceAccountId')
        if service_account:
            return _SigningProvider.from_iam(self.request, google_cred, service_account)

        # If the SDK was initialized with some other credential type that supports signing
        # (e.g. GAE credentials), use it to sign bytes.
        if isinstance(google_cred, credentials.Signing):
            return _SigningProvider.from_credential(google_cred)

        # Attempt to discover a service account email from the local Metadata service. Use it
        # with the IAM service to sign bytes.
        resp = self.request(url=METADATA_SERVICE_URL, headers={'Metadata-Flavor': 'Google'})
        if resp.status != 200:
            raise ValueError(
                'Failed to contact the local metadata service: {0}.'.format(resp.data.decode()))
        service_account = resp.data.decode()
        return _SigningProvider.from_iam(self.request, google_cred, service_account)

    @property
    def signing_provider(self):
        """Initializes and returns the SigningProvider instance to be used."""
        if not self._signing_provider:
            try:
                self._signing_provider = self._init_signing_provider()
            except Exception as error:
                url = 'https://firebase.google.com/docs/auth/admin/create-custom-tokens'
                raise ValueError(
                    'Failed to determine service account: {0}. Make sure to initialize the SDK '
                    'with service account credentials or specify a service account ID with '
                    'iam.serviceAccounts.signBlob permission. Please refer to {1} for more '
                    'details on creating custom tokens.'.format(error, url))
        return self._signing_provider

    def create_custom_token(self, uid, developer_claims=None):
        """Builds and signs a Firebase custom auth token."""
        if developer_claims is not None:
            if not isinstance(developer_claims, dict):
                raise ValueError('developer_claims must be a dictionary')

            disallowed_keys = set(developer_claims.keys()) & RESERVED_CLAIMS
            if disallowed_keys:
                if len(disallowed_keys) > 1:
                    error_message = ('Developer claims {0} are reserved and '
                                     'cannot be specified.'.format(
                                         ', '.join(disallowed_keys)))
                else:
                    error_message = ('Developer claim {0} is reserved and '
                                     'cannot be specified.'.format(
                                         ', '.join(disallowed_keys)))
                raise ValueError(error_message)

        if not uid or not isinstance(uid, six.string_types) or len(uid) > 128:
            raise ValueError('uid must be a string between 1 and 128 characters.')

        signing_provider = self.signing_provider
        now = int(time.time())
        payload = {
            'iss': signing_provider.signer_email,
            'sub': signing_provider.signer_email,
            'aud': FIREBASE_AUDIENCE,
            'uid': uid,
            'iat': now,
            'exp': now + MAX_TOKEN_LIFETIME_SECONDS,
        }

        if developer_claims is not None:
            payload['claims'] = developer_claims
        try:
            return jwt.encode(signing_provider.signer, payload)
        except google.auth.exceptions.TransportError as error:
            msg = 'Failed to sign custom token. {0}'.format(error)
            raise TokenSignError(msg, error)


    def create_session_cookie(self, id_token, expires_in):
        """Creates a session cookie from the provided ID token."""
        id_token = id_token.decode('utf-8') if isinstance(id_token, six.binary_type) else id_token
        if not isinstance(id_token, six.text_type) or not id_token:
            raise ValueError(
                'Illegal ID token provided: {0}. ID token must be a non-empty '
                'string.'.format(id_token))

        if isinstance(expires_in, datetime.timedelta):
            expires_in = int(expires_in.total_seconds())
        if isinstance(expires_in, bool) or not isinstance(expires_in, int):
            raise ValueError('Illegal expiry duration: {0}.'.format(expires_in))
        if expires_in < MIN_SESSION_COOKIE_DURATION_SECONDS:
            raise ValueError('Illegal expiry duration: {0}. Duration must be at least {1} '
                             'seconds.'.format(expires_in, MIN_SESSION_COOKIE_DURATION_SECONDS))
        if expires_in > MAX_SESSION_COOKIE_DURATION_SECONDS:
            raise ValueError('Illegal expiry duration: {0}. Duration must be at most {1} '
                             'seconds.'.format(expires_in, MAX_SESSION_COOKIE_DURATION_SECONDS))

        payload = {
            'idToken': id_token,
            'validDuration': expires_in,
        }
        try:
            body, http_resp = self.client.body_and_response(
                'post', ':createSessionCookie', json=payload)
        except requests.exceptions.RequestException as error:
            raise _auth_utils.handle_auth_backend_error(error)
        else:
            if not body or not body.get('sessionCookie'):
                raise _auth_utils.UnexpectedResponseError(
                    'Failed to create session cookie.', http_response=http_resp)
            return body.get('sessionCookie')


class TokenVerifier(object):
    """Verifies ID tokens and session cookies."""

    def __init__(self, app):
        session = cachecontrol.CacheControl(requests.Session())
        self.request = transport.requests.Request(session=session)
        self.id_token_verifier = _JWTVerifier(
            project_id=app.project_id, short_name='ID token',
            operation='verify_id_token()',
            doc_url='https://firebase.google.com/docs/auth/admin/verify-id-tokens',
            cert_url=_auth_utils.get_token_cert_url(),
            issuer=ID_TOKEN_ISSUER_PREFIX,
            invalid_token_error=_auth_utils.InvalidIdTokenError,
            expired_token_error=ExpiredIdTokenError)
        self.cookie_verifier = _JWTVerifier(
            project_id=app.project_id, short_name='session cookie',
            operation='verify_session_cookie()',
            doc_url='https://firebase.google.com/docs/auth/admin/verify-id-tokens',
            cert_url=_auth_utils.get_cookie_cert_url(),
            issuer=COOKIE_ISSUER_PREFIX,
            invalid_token_error=InvalidSessionCookieError,
            expired_token_error=ExpiredSessionCookieError)

    def verify_id_token(self, id_token):
        return self.id_token_verifier.verify(id_token, self.request)

    def verify_session_cookie(self, cookie):
        return self.cookie_verifier.verify(cookie, self.request)


class _JWTVerifier(object):
    """Verifies Firebase JWTs (ID tokens or session cookies)."""

    def __init__(self, **kwargs):
        self.project_id = kwargs.pop('project_id')
        self.short_name = kwargs.pop('short_name')
        self.operation = kwargs.pop('operation')
        self.url = kwargs.pop('doc_url')
        self.cert_url = kwargs.pop('cert_url')
        self.issuer = kwargs.pop('issuer')
        if self.short_name[0].lower() in 'aeiou':
            self.articled_short_name = 'an {0}'.format(self.short_name)
        else:
            self.articled_short_name = 'a {0}'.format(self.short_name)
        self._invalid_token_error = kwargs.pop('invalid_token_error')
        self._expired_token_error = kwargs.pop('expired_token_error')

    @property
    def verify_id_token_msg(self):
        return 'See {0} for details on how to retrieve {1}.'.format(self.url, self.short_name)

    @property
    def project_id_match_msg(self):
        return ('Make sure the {0} comes from the same Firebase project as the service account '
                'used to authenticate this SDK.'.format(self.short_name))

    @property
    def expected_issuer(self):
        return self.issuer + self.project_id

    def _decode_unverified(self, token):
        try:
            header = jwt.decode_header(token)
            payload = jwt.decode(token, verify=False)
            return header, payload
        except ValueError as error:
            raise self._invalid_token_error(str(error), cause=error)

    def _verify_aud(self, payload):
        audience = payload.get('aud')
        if audience == FIREBASE_AUDIENCE:
            raise self._invalid_token_error(
                '{0} expects {1}, but was given a custom '
                'token.'.format(self.operation, self.articled_short_name))
        elif audience != self.project_id:
            raise self._invalid_token_error(
                'Firebase {0} has incorrect "aud" (audience) claim. Expected "{1}" but got "{2}". '
                '{3} {4}'.format(self.short_name, self.project_id, audience,
                                 self.project_id_match_msg, self.verify_id_token_msg))

    def _verify_kid_and_alg(self, header, payload):
        key_id = header.get('kid')
        algorithm = header.get('alg')
        if not key_id:
            if algorithm == 'HS256' and payload.get('v') == 0 and 'uid' in payload.get('d', {}):
                raise self._invalid_token_error(
                    '{0} expects {1}, but was given a legacy custom '
                    'token.'.format(self.operation, self.articled_short_name))
            else:
                raise self._invalid_token_error(
                    'Firebase {0} has no "kid" claim.'.format(self.short_name))
        elif algorithm != 'RS256':
            raise self._invalid_token_error(
                'Firebase {0} has incorrect algorithm. Expected "RS256" but got "{1}". '
                '{2}'.format(self.short_name, algorithm, self.verify_id_token_msg))

    def _verify_iss(self, payload):
        issuer = payload.get('iss')
        if issuer != self.expected_issuer:
            raise self._invalid_token_error(
                'Firebase {0} has incorrect "iss" (issuer) claim. Expected "{1}" but '
                'got "{2}". {3} {4}'.format(self.short_name, self.expected_issuer, issuer,
                                            self.project_id_match_msg, self.verify_id_token_msg))

    def _verify_sub(self, payload):
        subject = payload.get('sub')
        if subject is None or not isinstance(subject, six.string_types):
            raise self._invalid_token_error(
                'Firebase {0} has no "sub" (subject) claim. '
                '{1}'.format(self.short_name, self.verify_id_token_msg))
        elif not subject:
            raise self._invalid_token_error(
                'Firebase {0} has an empty string "sub" (subject) claim. '
                '{1}'.format(self.short_name, self.verify_id_token_msg))
        elif len(subject) > 128:
            raise self._invalid_token_error(
                'Firebase {0} has a "sub" (subject) claim longer than 128 characters. '
                '{1}'.format(self.short_name, self.verify_id_token_msg))

    def _verify_iat_and_exp(self, payload):
        issued_at = payload.get('iat')
        expires_at = payload.get('exp')
        now = calendar.timegm(datetime.datetime.utcnow().utctimetuple())
        if not issued_at:
            raise self._invalid_token_error('Token does not contain required claim "iat"')
        elif not expires_at:
            raise self._invalid_token_error('Token does not contain required claim "exp"')
        elif now < issued_at - _CLOCK_SKEW_SECS:
            raise self._invalid_token_error(
                'Token used too early, {0} < {1}'.format(now, issued_at))
        elif now > expires_at + _CLOCK_SKEW_SECS:
            raise self._expired_token_error(
                'Token expired, {0} < {1}'.format(expires_at, now), cause=None)

    def _verify_token_signature(self, token, request):
        try:
            return google.oauth2.id_token.verify_token(
                token, request=request, audience=self.project_id, certs_url=self.cert_url)
        except google.auth.exceptions.TransportError as error:
            raise CertificateFetchError(str(error), cause=error)
        except ValueError as error:
            if 'Token expired' in str(error):
                raise self._expired_token_error(str(error), cause=error)
            raise self._invalid_token_error(str(error), cause=error)

    def verify(self, token, request):
        """Verifies the signature and data for the provided JWT."""
        token = token.encode('utf-8') if isinstance(token, six.text_type) else token
        if not isinstance(token, six.binary_type) or not token:
            raise ValueError(
                'Illegal {0} provided: {1}. {0} must be a non-empty '
                'string.'.format(self.short_name, token))

        if not self.project_id:
            raise ValueError(
                'Failed to ascertain project ID from the credential or the environment. Project '
                'ID is required to call {0}. Initialize the app with a credentials.Certificate '
                'or set your Firebase project ID as an app option. Alternatively set the '
                'GOOGLE_CLOUD_PROJECT environment variable.'.format(self.operation))

        header, payload = self._decode_unverified(token)

        self._verify_aud(payload)
        self._verify_iss(payload)
        self._verify_sub(payload)

        if _auth_utils.is_emulator_enabled():
            # NOTE: `_verify_token_signature` handles `iat` and `exp` verification as a byproduct,
            # but we do not want to check signatures while running in emulator-mode so we explicitly
            # check `iat` and `exp` ourselves instead.
            self._verify_iat_and_exp(payload)
        else:
            self._verify_kid_and_alg(header, payload)
            self._verify_token_signature(token, request)

        payload['uid'] = payload['sub']
        return payload


class TokenSignError(exceptions.UnknownError):
    """Unexpected error while signing a Firebase custom token."""

    def __init__(self, message, cause):
        exceptions.UnknownError.__init__(self, message, cause)


class CertificateFetchError(exceptions.UnknownError):
    """Failed to fetch some public key certificates required to verify a token."""

    def __init__(self, message, cause):
        exceptions.UnknownError.__init__(self, message, cause)


class ExpiredIdTokenError(_auth_utils.InvalidIdTokenError):
    """The provided ID token is expired."""

    def __init__(self, message, cause):
        _auth_utils.InvalidIdTokenError.__init__(self, message, cause)


class RevokedIdTokenError(_auth_utils.InvalidIdTokenError):
    """The provided ID token has been revoked."""

    def __init__(self, message):
        _auth_utils.InvalidIdTokenError.__init__(self, message)


class InvalidSessionCookieError(exceptions.InvalidArgumentError):
    """The provided string is not a valid Firebase session cookie."""

    def __init__(self, message, cause=None):
        exceptions.InvalidArgumentError.__init__(self, message, cause)


class ExpiredSessionCookieError(InvalidSessionCookieError):
    """The provided session cookie is expired."""

    def __init__(self, message, cause):
        InvalidSessionCookieError.__init__(self, message, cause)


class RevokedSessionCookieError(InvalidSessionCookieError):
    """The provided session cookie has been revoked."""

    def __init__(self, message):
        InvalidSessionCookieError.__init__(self, message)
