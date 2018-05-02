from django.db import models
from django.contrib.auth.models import AbstractUser

from barrier_field.client import cognito
from barrier_field.utils import get_attr_map, \
    get_custom_attrs_from_options


class User(AbstractUser):
    """
    Extend base django user to include phone number, which is required by
    cognito
    """
    phone_number = models.CharField(max_length=50, blank=True)

    def save(self, update_cognito=True, *args, **kwargs):
        if self.username[0:13] == '__temporary__':
            update_cognito = False
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
        if not cognito_data.pop('is_active'):
            # Do something about disabling the user in cognito here
            pass
        cognito.username = cognito_data.pop('username')
        cognito_data.update(**get_custom_attrs_from_options(cognito_data))
        cognito.admin_update_profile(
            cognito_data, attr_map=get_attr_map()
        )
