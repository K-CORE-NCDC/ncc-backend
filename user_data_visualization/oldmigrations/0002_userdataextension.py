# Generated by Django 3.2.6 on 2024-06-21 08:45

import django.contrib.postgres.fields.jsonb
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('user_data_visualization', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='UserDataExtension',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('user', models.CharField(max_length=255, unique=True)),
                ('project_name', models.CharField(max_length=255, unique=True)),
                ('project_id', models.IntegerField(blank=True, null=True)),
                ('available_steps', django.contrib.postgres.fields.jsonb.JSONField(default=dict)),
                ('uploaded_date', models.DateTimeField(auto_now=True, null=True)),
                ('extended_on', models.DateTimeField(null=True)),
                ('reason_for_extension', models.TextField(default=None, null=True)),
                ('deleted_on', models.DateTimeField(null=True)),
            ],
        ),
    ]
