from django.contrib.auth import authenticate, login


from barrier_field.client import cognito_client
from barrier_field.utils import get_attr_map, is_enabled, get_user_model


class CognitoAuth:
    Users = get_user_model()
    cognito = cognito_client()
    cognito_mapping = get_attr_map()

    def get_user(self, request):
        return self.Users.objects.get(pk=request)

    def authenticate(self, request, username=None, password=None,
                     cognito_auth=None):
        """
        Authenticate with cognito. If authentication is success the cognito
        user will be sync'ed with local cache.
        :param request:
        :param username:
        :param password:
        :param cognito_auth: If cognito user has already been authorised,
        and you are completing authentication (for example, force changing
        password or completeing MFA), send the authorised cognito token
        :return:
        """
        self.cognito.username = username

        if not is_enabled():
            return None

        if not cognito_auth:
            # New user session authentication
            try:
                self.cognito.authenticate(password, request)
            except Exception as e:
                self.update_session(request)
                resp = self.cognito.auth_error_handler(e)
                return resp
        else:
            # Validate authentication
            self.cognito.verify_token(
                cognito_auth['AuthenticationResult']['IdToken'],
                'id_token', 'id'
            )
            self.cognito.verify_token(
                cognito_auth['AuthenticationResult']['AccessToken'],
                'access_token', 'access'
            )

        self.update_session(request)
        user = self.cognito.get_user(self.cognito_mapping)
        self.cognito.sync_cache(user)
        cache_user = self.Users.objects.get(email=user.pk)
        return cache_user

    def update_session(self, request):
        """
            Add refresh token to the session so it can be accessed
        """
        if getattr(request, 'session', False):
            request.session['cognito_auth'] = {
                'access_token': self.cognito.access_token,
                'refresh_token': self.cognito.refresh_token,
                'token_type': self.cognito.token_type,
                'id_token': self.cognito.id_token
            }


def complete_login(request, auth_response, username):
    user = authenticate(
        request, username=username, cognito_auth=auth_response
    )
    login(request, user)
