import datetime
from os import listdir, stat, remove
from pathlib import Path

from django.conf import settings

from barrier_field.client import cognito


class RefreshCognito:
    """Update Cognito with auth details from session"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Refresh local cognito session
        if (
            request.user.is_authenticated and
            request.session.get('cognito_auth') and
            not cognito.access_token
        ):
            cognito_auth_session = request.session['cognito_auth']
            cognito.access_token = cognito_auth_session['access_token']
            cognito.refresh_token = cognito_auth_session['refresh_token']
            cognito.token_type = cognito_auth_session['token_type']
            cognito.id_token = cognito_auth_session['id_token']

        # Clean up QR codes
        temp_path = Path(getattr(settings, 'QR_CODE_PATH', 'static/temp/QR'))
        if not temp_path.exists():
            return response
        for file in listdir(temp_path):
            path_to_file = f'{temp_path}/{file}'
            file_stats = stat(path_to_file)
            date_modified = datetime.datetime.fromtimestamp(file_stats.st_mtime)
            time_diff = (
                    datetime.datetime.now() -
                    date_modified
            ).seconds / 60
            if time_diff > 30:
                remove(path_to_file)

        return response
