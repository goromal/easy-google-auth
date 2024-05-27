import os
import json
import requests
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

class CredentialsRefreshException(Exception):
    pass

def _revoke_token(token):
    response = requests.post(
        'https://accounts.google.com/o/oauth2/revoke',
        params={'token': token},
        headers={'content-type': 'application/x-www-form-urlencoded'}
    )
    if response.status_code == 200:
        return True
    else:
        return False

def _refresh_creds(refresh_token, secrets_file, scope, headless):
    if headless:
        raise CredentialsRefreshException("Cannot refresh credentials in headless mode.")
    if os.path.exists(refresh_token):
        with open(refresh_token, "r") as token_file:
            token = json.loads(token_file.read())["token"]
        if not _revoke_token(token):
            raise CredentialsRefreshException("Unable to revoke token.")
        os.remove(refresh_token)
    flow = InstalledAppFlow.from_client_secrets_file(secrets_file, scope)
    return flow.run_local_server(port=0)

def getGoogleService(api_name, version, secrets_file, refresh_token, scope, headless=False, force=False):
    creds = None
    if force:
        creds = _refresh_creds(refresh_token, secrets_file, scope, headless)
        with open(refresh_token, "w") as token:
            token.write(creds.to_json())
    else:    
        if os.path.exists(refresh_token):
            creds = Credentials.from_authorized_user_file(refresh_token, scope)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except RefreshError:
                    creds = _refresh_creds(refresh_token, secrets_file, scope, headless)
            else:
                creds = _refresh_creds(refresh_token, secrets_file, scope, headless)
            with open(refresh_token, "w") as token:
                token.write(creds.to_json())
    return build(api_name, version, credentials=creds)
