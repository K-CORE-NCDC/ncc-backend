# Generated by Django 3.2.6 on 2024-11-21 12:03

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0005_auto_20241121_1138'),
    ]

    operations = [
        migrations.AddField(
            model_name='clinicalinformation',
            name='stage',
            field=models.CharField(blank=True, max_length=155, null=True),
        ),
    ]
