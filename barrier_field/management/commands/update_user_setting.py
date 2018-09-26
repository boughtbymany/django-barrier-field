from django.core.management import BaseCommand

from barrier_field.client import cognito_client


class Command(BaseCommand):
    help = 'Verify email address or phone number'

    def add_arguments(self, parser):
        parser.add_argument('username')
        parser.add_argument('--key')
        parser.add_argument('--value')

    def handle(self, *args, **options):
        cognito = cognito_client()
        username = options['username']
        cognito.username = username

        key = options['key']
        value = options['value']

        if not key and value:
            raise Exception('Key and value required.')

        cognito.admin_update_profile(
            {key: value}
        )
        self.stdout.write(f'User {username} unverified')
