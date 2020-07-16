import re
from typing import List
import urllib.parse

import requests
from google.auth.transport import requests as google_requests
from google.oauth2 import service_account

from .infrastructure import AuthAdapter


class DummyOAuth(AuthAdapter):
  """Auth adapter that gets JWTs that uses the Dummy OAuth Server"""

  def __init__(self, token_endpoint: str, sub: str):
    super().__init__()

    self._oauth_token_endpoint = token_endpoint
    self._sub = sub
    self._oauth_session = requests.Session()

  # Overrides method in AuthAdapter
  def issue_token(self, intended_audience: str, scopes: List[str]) -> str:
    url = '{}?grant_type=client_credentials&scope={}&intended_audience={}&issuer=dummy&sub={}'.format(
      self._oauth_token_endpoint, urllib.parse.quote(' '.join(scopes)),
      urllib.parse.quote(intended_audience), self._sub)
    response = self._oauth_session.post(url).json()
    return response['access_token']


class ServiceAccount(AuthAdapter):
  """Auth adapter that gets JWTs using a service account."""

  def __init__(self, token_endpoint: str, service_account_json: str):
    super().__init__()

    credentials = service_account.Credentials.from_service_account_file(
      service_account_json).with_scopes(['email'])
    oauth_session = google_requests.AuthorizedSession(credentials)

    self._oauth_token_endpoint = token_endpoint
    self._oauth_session = oauth_session

  # Overrides method in AuthAdapter
  def issue_token(self, intended_audience: str, scopes: List[str]) -> str:
    url = '{}?grant_type=client_credentials&scope={}&intended_audience={}'.format(
      self._oauth_token_endpoint, urllib.parse.quote(' '.join(scopes)),
      urllib.parse.quote(intended_audience))
    response = self._oauth_session.post(url).json()
    return response['access_token']


class UsernamePassword(AuthAdapter):
  """Auth adapter that gets JWTs using a username and password."""

  def __init__(self, token_endpoint, username, password, client_id):
    super().__init__()

    self._oauth_token_endpoint = token_endpoint
    self._username = username
    self._password = password
    self._client_id = client_id

  # Overrides method in AuthAdapter
  def issue_token(self, intended_audience: str, scopes: List[str]) -> str:
    scopes.append('aud:{}'.format(intended_audience))
    response = requests.post(self._oauth_token_endpoint, data={
      'grant_type': "password",
      'username': self._username,
      'password': self._password,
      'client_id': self._client_id,
      'scope': ' '.join(scopes),
    }).json()
    return response['access_token']


def make_auth_adapter(spec: str) -> AuthAdapter:
  """Make an AuthAdapter according to a string specification.

  :param spec: Specification of adapter in the form
               ADAPTER_NAME([VALUE1[,PARAM2=VALUE2][,...]]) where ADAPTER_NAME
               is the name of a subclass of AuthAdapter and the contents of the
               parentheses are *args-style and **kwargs-style values for the
               parameters of ADAPTER_NAME's __init__, but the values (all
               strings) do not have any quote-like delimiters.
  :return: An instance of the appropriate AuthAdapter subclass according to the
           provided spec.
  """
  m = re.match(r'^\s*([^\s(]+)\s*\(\s*([^)]*)\s*\)\s*$', spec)
  if m is None:
    raise ValueError('Auth adapter specification did not match the pattern `AdapterName(param, param, ...)`')

  adapter_name = m.group(1)
  adapter_classes = {cls.__name__: cls for cls in AuthAdapter.__subclasses__()}
  if adapter_name not in adapter_classes:
    raise ValueError('Auth adapter `%s` does not exist' % adapter_name)
  Adapter = adapter_classes[adapter_name]

  adapter_param_string = m.group(2)
  param_strings = [s.strip() for s in adapter_param_string.split(',')]
  args = []
  kwargs = {}
  for param_string in param_strings:
    if '=' in param_string:
      kv = param_string.split('=')
      if len(kv) != 2:
        raise ValueError('Auth adapter specification contained a parameter with more than one `=` character')
      kwargs[kv[0].strip()] = kv[1].strip()
    else:
      args.append(param_string)

  return Adapter(*args, **kwargs)
