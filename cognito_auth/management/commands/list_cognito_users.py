import json

from django.core.management import BaseCommand

from cognito_auth.client import cognito


class Command(BaseCommand):
    help = 'List all cognito users'

    def handle(self, *args, **options):
        users = cognito.get_users()
        display_users = []
        for user in users:
            info = {
                'key': user.pk,
                'username': user.email,
                'data': user._data
            }
            display_users.append(info)
        self.stdout.write(json.dumps(display_users, indent=4))

