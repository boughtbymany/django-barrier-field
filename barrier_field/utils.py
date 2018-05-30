import random
import secrets
import string

from django.apps import apps
from django.conf import settings

def is_enabled():
    cognito_auth = getattr(settings, 'COGNITO_ENABLED', None)
    if cognito_auth is not None and cognito_auth is False:
        return False
    if not settings.AWS_ACCESS_KEY_ID or not settings.AWS_SECRET_ACCESS_KEY:
        return False
    return True

def get_custom_attrs():
    """
    Returns either the default custom attribute definitions, or fetches
    it from the settings.

    Custom attribute definition requires the name of the attribute as the
    name and the type of the attribute as the value.

    'custom:' will be prepended to the name of each attribute when the map
    is being built bu the 'get_attribute_map()' function.
    """
    default_custom_attrs = {
        'is_superuser': bool,
        'is_staff': bool
    }
    return getattr(settings, 'CUSTOM_ATTRS', default_custom_attrs)


def get_standard_attrs():
    """
    Returns either the default standard attribute definitions, or fetches
    it from the settings.

    This is a map of values from cognito to the local cache.

    The name of each attribute should be the name of the attribute in cognito
    and the value should be the local name. All the cognito standard attributes
    can be found in the "Attributes" tab of a cognito User Pool.
    """
    default_attr_map = {
        'given_name': 'first_name',
        'family_name': 'last_name',
    }
    return getattr(settings, 'STANDARD_ATTRS', default_attr_map)


def get_required_attrs():
    """
    Returns either the default required attribute definitions, or fetches
    it from the settings.

    This is used in conjunction with the command line tools, and defines
    whether an attribute should be required when creating a new cognito user.
    """
    default_required_attrs = []
    return getattr(settings, 'REQUIRED_ATTRS', default_required_attrs)


def get_attr_map():
    """
    Combines the custom and standard attributes into a full attribute map
    for creating or updating users in cognito from a local cache
    """
    custom_attributes = get_custom_attrs()
    standard_attributes = get_standard_attrs()
    mapping = {}
    for attr in custom_attributes.keys():
        mapping[f'custom:{attr}'] = attr
    mapping.update(standard_attributes)
    return mapping


def get_custom_attrs_from_options(options):
    """
    This pulls the custom attributes from the options when creating a new user
    with the command line tools, and formats them to make them acceptable to
    cognito
    """
    custom_attrs = get_custom_attrs()
    custom_attributes = {}
    for attr in custom_attrs.keys():
        if attr in options.keys():
            if custom_attrs[attr] == str:
                custom_attributes[attr] = options[attr]
            elif custom_attrs[attr] == int:
                custom_attributes[attr] = str(options[attr])
            elif custom_attrs[attr] == bool:
                custom_attributes[attr] = str(int(options[attr]))
            else:
                raise AttributeError()
    return custom_attributes


def make_password_requirements():
    requirements_list = getattr(settings, 'PASSWORD_REQUIREMENTS', [])
    requirements = []
    if 'special-character' in requirements_list:
        requirements.append(random.choice(string.punctuation))
    if 'upper-case' in requirements_list:
        requirements.append(random.choice(string.ascii_uppercase))
    if 'lower-case' in requirements_list:
        requirements.append(random.choice(string.ascii_lowercase))
    if 'number' in requirements_list:
        requirements.append(random.choice(string.digits))
    return requirements


def generate_temporary_password():
    """
    Generate temporary passwords that cognito will accept. Must have a special
    character and an upper case character
    """
    password_length = getattr(
        settings, 'PASSWORD_LENGTH', 8
    )
    base_password = secrets.token_hex(int(password_length / 2))
    requirements = make_password_requirements()
    password = list(base_password)
    password.extend(requirements)
    random.shuffle(password)
    return "".join(password)


def get_user_data_model():
    """
    If a user data model has been specified in the settings, return the model.
    Otherwise return False
    """
    data_model_location =  getattr(settings, 'USER_DATA_MODEL', False)
    if data_model_location:
        return apps.get_model(
            data_model_location, require_ready=False
        )
    else:
        return False


def get_user_data_model_fields():
    """
    If a user data model exists, return all the fields of the model. Otherwise
    return False
    """
    user_data_model = get_user_data_model()
    if user_data_model:
        data_model_fields = [
            field.name for field in user_data_model._meta.fields
        ]
        return data_model_fields
    else:
        return False
