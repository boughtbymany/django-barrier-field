from django.core.management import BaseCommand

from cognito_auth.client import cognito


class Command(BaseCommand):
    help = 'Confirm a user in cognito.'

    def add_arguments(self, parser):
        parser.add_argument('username')

    def handle(self, *args, **options):
        username = options['username']
        try:
            cognito.admin_confirm_sign_up(username)
        except Exception as e:
            self.stderr.write(f'Error: {e}')
        self.stdout.write(f'User {username} confirmed')

