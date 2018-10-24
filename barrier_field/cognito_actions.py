from django.forms.models import model_to_dict
from django.conf import settings
from warrant import Cognito


def register(new_user):
    new_user = model_to_dict(new_user) if not type(
        new_user) == dict else new_user
    pool_id = settings.COGNITO_USER_POOL_ID
    app_id = settings.COGNITO_APP_ID
    cog = Cognito(pool_id, app_id)
    cog.add_base_attributes(email=new_user['email'])
    cog.add_custom_attributes(
        is_staff=str(int(new_user['is_staff'])),
        is_superuser=str(int(new_user['is_superuser']))
    )
    cog.register(new_user['email'], new_user['password'])
