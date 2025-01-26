import os
import time
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build

_SCOPE = [
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/tasks",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/photoslibrary",
]


class CredentialsRefreshException(Exception):
    pass


def _refresh_creds(refresh_token, secrets_file, scope, headless, headless_refresh):
    if headless and not headless_refresh:
        raise CredentialsRefreshException(
            "Cannot refresh credentials in headless mode."
        )
    if os.path.exists(refresh_token):
        os.remove(refresh_token)
    if not headless_refresh:
        flow = InstalledAppFlow.from_client_secrets_file(secrets_file, scope)
        return flow.run_local_server(port=0)
    else:
        flow = InstalledAppFlow.from_client_secrets_file(
            secrets_file, scope, redirect_uri="urn:ietf:wg:oauth:2.0:oob"
        )
        auth_url, _ = flow.authorization_url(prompt="consent")
        print(f"\n{auth_url}\n")
        auth_code = input(
            "Visit the URL above, complete the authorization, and paste here:"
        )
        flow.fetch_token(code=auth_code.strip())
        return flow.credentials


def getGoogleCreds(secrets_file, refresh_token, headless=False, force=False):
    secrets_file = os.path.expanduser(secrets_file)
    refresh_token = os.path.expanduser(refresh_token)
    creds = None
    if force:
        creds = _refresh_creds(
            refresh_token, secrets_file, _SCOPE, headless, headless and force
        )
        with open(refresh_token, "w") as token:
            token.write(creds.to_json())
    else:
        if os.path.exists(refresh_token):
            creds = Credentials.from_authorized_user_file(refresh_token, _SCOPE)
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                try:
                    creds.refresh(Request())
                except RefreshError:
                    creds = _refresh_creds(
                        refresh_token,
                        secrets_file,
                        _SCOPE,
                        headless,
                        headless and force,
                    )
            else:
                creds = _refresh_creds(
                    refresh_token, secrets_file, _SCOPE, headless, headless and force
                )
            with open(refresh_token, "w") as token:
                token.write(creds.to_json())
    return creds


class RateLimitedService:
    def __init__(self, service, max_rate_per_sec):
        self._service = service
        self._max_rate = float(max_rate_per_sec)
        self._min_interval = 1.0 / float(self._max_rate)
        self._last_call_time = 0
    
    def __getattr__(self, name):
        attr = getattr(self._service, name)
        if callable(attr):
            def wrapped_method(*args, **kwargs):
                current_time = time.time()
                elapsed_time = current_Time - self._last_call_time
                if elapsed_time < self._min_interval:
                    time_to_wait = self._min_interval - elapsed_time
                    # Need to rate limit
                    time.sleep(time_to_wait)
                self._last_call_time = time.time()
                return attr(*args, **kwargs)
            return wrapped_method
        return attr

def getGoogleService(
    api_name, version, secrets_file, refresh_token, headless=False, force=False
):
    return build(
        api_name,
        version,
        static_discovery=False,
        credentials=getGoogleCreds(secrets_file, refresh_token, headless, force),
    )

def getRateLimitedGoogleService(
    api_name, version, secrets_file, refresh_token, headless=False, force=False, max_rate_per_sec=2.0
):
    service = build(
        api_name,
        version,
        static_discovery=False,
        credentials=getGoogleCreds(secrets_file, refresh_token, headless, force),
    )
    return RateLimitedService(service, max_rate_per_sec)
