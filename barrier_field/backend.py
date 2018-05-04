from django.apps import apps
from django.conf import settings
from django.contrib.auth import get_user_model, authenticate, login
from warrant import Cognito

from barrier_field.client import cognito
from barrier_field.utils import get_attr_map, get_user_data_model_fields, \
    get_user_data_model


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
        :param cognito_auth: If cognito user has already been authorised,
        and you are completing authentication (for example, force changing
        password or completeing MFA), send the authorised cognito token
        :return:
        """
        cognito_user = cognito

        if not cognito_auth:
            # New user session authentication
            cognito_user = cognito
            cognito.username = username
            try:
                cognito_user.authenticate(password, request)
            except Exception as e:
                resp = cognito.auth_error_handler(e)
                return resp
        else:
            # Validate authentication
            cognito.verify_token(
                cognito_auth['AuthenticationResult']['IdToken'],
                'id_token','id'
            )
            cognito.verify_token(
                cognito_auth['AuthenticationResult']['AccessToken'],
                'access_token', 'access'
            )

        self.update_session(request)
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

                cognito_data = cognito_user._data

                user_data_fields = get_user_data_model_fields()
                if user_data_fields:
                    user_data_update = {}
                    for field in [*cognito_data.keys()].copy():
                        if field in user_data_fields:
                            user_data_update[field] = cognito_data.pop(field)

                    # Update user data
                    user_data_object = get_user_data_model().objects.filter(
                        pk=local_user.user_data_id
                    )
                    user_data_object.update(**user_data_update)

                for field in cognito_data.keys():
                    cognito_field_value = getattr(cognito_user, field)
                    if isinstance(getattr(local_user, field), bool):
                        cognito_field_value = bool(int(cognito_field_value))
                    setattr(local_user, field, cognito_field_value)

                local_user.save()
            except self.Users.DoesNotExist:
                # Create new cached user

                # First check whether a custom data model exists
                user_data_fields = get_user_data_model_fields()
                if user_data_fields:
                    compiled_user_data = {}
                    for field in user_data_fields:
                        if field in cognito_user._data.keys():
                            user_data = cognito_user._data.pop(field)
                            compiled_user_data[field] = user_data
                    user_data = get_user_data_model().objects.create(
                        **compiled_user_data
                    )

                    self.Users.objects.create_user(
                        username=cognito_user.username, password=None,
                        user_data=user_data, **cognito_user._data
                    )
                else:
                    self.Users.objects.create_user(
                        username=cognito_user.username, password=None,
                        **cognito_user._data
                    )

    def update_session(self, request):
        """
            Add refresh token to the session so it can be accessed
        """
        if getattr(request, 'session', False):
            request.session['cognito_auth'] = {
                'access_token': cognito.access_token,
                'refresh_token': cognito.refresh_token,
                'token_type': cognito.token_type,
                'id_token': cognito.id_token
            }


def complete_login(request, auth_response):
    user = authenticate(request, cognito_auth=auth_response)
    login(request, user)
