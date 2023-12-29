import os
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

def getGoogleService(api_name, version, secrets_file, refresh_token, scope, headless=False):
    creds = None
    if os.path.exists(refresh_token):
        creds = Credentials.from_authorized_user_file(refresh_token, scope)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except RefreshError:
                if headless:
                    return None
                os.remove(refresh_token)
                flow = InstalledAppFlow.from_client_secrets_file(secrets_file, scope)
                creds = flow.run_local_server(port=0)
        else:
            if headless:
                return None
            flow = InstalledAppFlow.from_client_secrets_file(secrets_file, scope)
            creds = flow.run_local_server(port=0)
        with open(refresh_token, "w") as token:
            token.write(creds.to_json())
    return build(api_name, version, credentials=creds)
