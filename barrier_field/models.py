from django.apps import apps
from django.conf import settings
from django.db import models
from django.contrib.auth.models import AbstractUser

from barrier_field.client import cognito
from barrier_field.utils import get_attr_map, \
    get_custom_attrs_from_options, get_user_data_model


class User(AbstractUser):
    """
    Extend base django user to include phone number, which is required by
    cognito
    """
    phone_number = models.CharField(max_length=50, blank=True)

    user_data_model = getattr(settings, 'USER_DATA_MODEL', False)
    if user_data_model:
        user_data = models.ForeignKey(
            user_data_model, on_delete=models.CASCADE,
            blank=True, null=True
        )

    def save(self, update_cognito=True, *args, **kwargs):
        if update_cognito:
            self.sync_cognito()
        return super(User, self).save(*args, **kwargs)

    def sync_cognito(self):
        user_data = self.__dict__
        cognito_data = {}
        for data in user_data.keys():
            # Remove default django stuff
            if data in [
                '_state', 'id', 'password', 'last_login', 'date_joined',
                'backend', '_password'
            ]:
                continue
            cognito_data[data] = user_data[data]

        cognito.username = cognito_data.pop('username')

        # Enable/disable cognito user based on 'is_active'
        if not cognito_data.pop('is_active'):
            cognito.admin_disable_user()
        else:
            cognito.admin_enable_user()

        # If user data model exists, remove foreign key from data
        if get_user_data_model():
            cognito_data.pop('user_data_id')

        cognito_data.update(**get_custom_attrs_from_options(cognito_data))
        cognito.admin_update_profile(
            cognito_data, attr_map=get_attr_map()
        )
