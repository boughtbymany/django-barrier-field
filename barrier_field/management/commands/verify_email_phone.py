from django.core.management import BaseCommand

from barrier_field.client import cognito_client


class Command(BaseCommand):
    help = 'Verify email address or phone number'

    def add_arguments(self, parser):
        parser.add_argument('username')

    def handle(self, *args, **options):
        cognito = cognito_client()
        username = options['username']
        cognito.username = username

        cognito.admin_update_profile(
            {'email_verified': str('true')}
        )
        self.stdout.write(f'User {username} unverified')
