# Generated by Django 2.0.4 on 2018-05-02 15:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('barrier_field', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='phone_number',
            field=models.CharField(blank=True, max_length=50),
        ),
    ]
