# Generated by Django 2.1.2 on 2018-10-25 10:58

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('barrier_field', '0002_auto_20181025_1047'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='user',
            options={},
        ),
        migrations.RemoveField(
            model_name='user',
            name='username',
        ),
    ]
