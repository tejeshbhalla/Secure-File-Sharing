# Generated by Django 3.2.2 on 2023-04-09 01:52

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('content', '0013_auto_20230409_0152'),
    ]

    operations = [
        migrations.AddField(
            model_name='files_model',
            name='uploadinfo',
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name='folder',
            name='date_modified',
            field=models.DateTimeField(default=datetime.datetime(2023, 4, 9, 1, 52, 47, 649415)),
        ),
    ]
