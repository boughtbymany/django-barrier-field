# Generated by Django 2.0.4 on 2018-05-02 15:52

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('policiesio', '__first__'),
        ('barrier_field', '0002_auto_20180502_1523'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='user_data',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='policiesio.UserDetails'),
        ),
    ]
