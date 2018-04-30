from django.conf import settings
from django.core.management.base import BaseCommand
from django.core.validators import validate_email
from django.core.exceptions import ValidationError

from barrier_field.client import cognito
from barrier_field.utils import get_attr_map, \
    get_custom_attrs_from_options, get_custom_attrs, \
    generate_temporary_password, get_required_attrs


class Command(BaseCommand):
    help = 'Create a new user in cognito'

    def add_arguments(self, parser):
        # Required fields
        parser.add_argument(
            'username', type=str,
            help='Username in the form of an email address.'
        )
        parser.add_argument(
            '--temporary_password', type=str,
            help='This temporary password will be used the first '
                 'time the user logs in, at which time they were be '
                 'prompted to set a new password.'
        )
        parser.add_argument(
            '--telephone', type=str, help='Start with dialcode, eg +44'
        )

        # Add arguments for custom attributes
        custom_attrs = get_custom_attrs()
        required_attrs = get_required_attrs()
        for attr in custom_attrs.keys():
            if attr in required_attrs:
                if custom_attrs[attr] == bool:
                    parser.add_argument(
                        f'{attr.replace("_", "-")}', action='store_true'
                    )
                else:
                    parser.add_argument(
                        f'{attr.replace("_", "-")}', type=custom_attrs[attr]
                    )
            else:
                if custom_attrs[attr] == bool:
                    parser.add_argument(
                        f'--{attr.replace("_", "-")}', action='store_true'
                    )
                else:
                    parser.add_argument(
                        f'--{attr.replace("_", "-")}', type=custom_attrs[attr]
                    )

    def handle(self, *args, **options):
        # Validate and create user in cognito
        # Check username format
        username = options['username']
        try:
            validate_email(username)
        except ValidationError:
            self.stderr.write('Username must be an email address')

        password = options.get('temporary_password')
        if not password:
            password = generate_temporary_password()

        base_attributes = {
            'email': username
        }

        # Check telephone format
        telephone = options.get('telephone')
        if telephone:
            if telephone[0] != '+':
                dial_code = getattr(settings, 'DEFAULT_DIAL_CODE', '+44')
                if dial_code == '+44' and telephone[0] == '0':
                    telephone = dial_code + telephone[1:]
                else:
                    telephone = dial_code + telephone
            # Add to base attributes
            base_attributes['phone_number'] = telephone

        # Create a dict of all basic user info to print out
        complete_user = {'username': username, 'temp_password': password}
        complete_user.update(base_attributes)

        custom_attributes = get_custom_attrs_from_options(options)

        cognito.add_base_attributes(**base_attributes)
        cognito.admin_create_user(username, password)

        # Update user with optional and custom attributes
        cognito.username = username
        base_attributes.update(custom_attributes)
        cognito.admin_update_profile(
            base_attributes, attr_map=get_attr_map()
        )
        self.stdout.write(f'User successfully created! {complete_user}')