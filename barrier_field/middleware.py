from barrier_field.client import cognito


class RefreshCognito:
    """Update Cognito with auth details from session"""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        if (request.user.is_authenticated and
                request.session.get('cognito_auth') and
                not cognito.access_token
        ):
            cognito_auth_session = request.session['cognito_auth']
            cognito.access_token = cognito_auth_session['access_token']
            cognito.refresh_token = cognito_auth_session['refresh_token']
            cognito.token_type = cognito_auth_session['token_type']
            cognito.id_token = cognito_auth_session['id_token']

        return response