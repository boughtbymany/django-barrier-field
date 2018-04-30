from django.core.management import BaseCommand

from cognito_auth.client import cognito


class Command(BaseCommand):
    help = 'Remove a user from cognito'

    def add_arguments(self, parser):
        parser.add_argument('username')

    def handle(self, *args, **options):
        username = options['username']
        cognito.username = username
        cognito.admin_delete_user()
        self.stdout.write(f'User {username} deleted')

