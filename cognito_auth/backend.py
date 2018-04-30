from django.conf import settings
from django.contrib.auth import get_user_model, authenticate, login
from warrant import Cognito
from warrant.exceptions import ForceChangePasswordException

from cognito_auth.client import cognito
from cognito_auth.exceptions import MFARequiredSMS, MFARequiredSoftware
from cognito_auth.utils import get_attr_map


def register(request, new_user):
    pool_id = settings.COGNITO_USER_POOL_ID
    app_id = settings.COGNITO_APP_ID
    cog = Cognito(pool_id, app_id)
    cog.add_base_attributes(email=new_user['username'])
    cog.add_custom_attributes(
        is_staff=str(int(new_user['is_staff'])),
        is_superuser=str(int(new_user['is_superuser']))
    )
    cog.register(new_user['username'], new_user['password'])

class CognitoAuth:
    Users = get_user_model()
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
        :return:
        """
        if cognito_auth:
            # If user already authenticated with MFA
            cognito.access_token = cognito_auth['AuthenticationResult']['AccessToken']
            cognito_user = cognito
            user = cognito_user.get_user(self.cognito_mapping)
            self.sync_cache(user)
            cache_user = self.Users.objects.get(username=user.pk)
            return cache_user
        else:
            # New user session authentication
            cognito_user = cognito
            cognito.username = username
            try:
                cognito_user.authenticate(password, request)
            except Exception as e:
                self.auth_error_handler(e, cognito_user, password)
            user = cognito_user.get_user(self.cognito_mapping)
            self.sync_cache(user)
            cache_user = self.Users.objects.get(username=user.pk)
            return cache_user

    def sync_cache(self, cognito_user, deactivate=False):
        """
        Check and update local user data, and sync with cognito data if needed
        :param cognito_user:
        :param deactivate: if True, is_active of local user will be set to
        False. This will be run in the case of the cognito user being disabled.
        :return:
        """
        if deactivate:
            local_user = self.Users.objects.get(
                username=cognito_user['username']
            )
            local_user.is_active = False
            local_user.save()
        else:
            try:
                local_user = self.Users.objects.get(username=cognito_user.pk)
                if not local_user.is_active:
                    # Reactive user
                    local_user.is_active = True

                # Update fields
                for field in cognito_user._data.keys():
                    cognito_field_value = getattr(cognito_user, field)
                    if isinstance(getattr(local_user, field), bool):
                        cognito_field_value = bool(int(cognito_field_value))
                    setattr(local_user, field, cognito_field_value)

                local_user.save()
            except self.Users.DoesNotExist as e:
                # Create new cached user
                self.Users.objects.create_user(
                    username=cognito_user.username, password=None,
                    **cognito_user._data
                )

    def auth_error_handler(self, exception, cognito_user, password):
        if isinstance(exception, ForceChangePasswordException):
            # Prompt user to update their password here. Redirect to view.
            raise ForceChangePasswordException()
        elif isinstance(exception, MFARequiredSMS):
            raise MFARequiredSMS()
        elif isinstance(exception, MFARequiredSoftware):
            raise MFARequiredSoftware()
        else:
            # Handle botocore exceptions
            if not getattr(exception, 'response', False):
                raise exception
            error = exception.response.get('Error')
            if error:
                if error['Code'] == 'NotAuthorizedException':
                    # Handle disabled user
                    if error['Message'] == 'User is disabled':
                        self.sync_cache(
                            {'username': cognito_user.username}, deactivate=True
                        )
                    raise exception
            else:
                raise exception


def complete_login(request, auth_response):
    user = authenticate(request, cognito_auth=auth_response)
    login(request, user)
