# Generated by Django 3.0.5 on 2021-12-01 01:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('okta_oauth2', '0002_auto_20211129_1919'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userdetails',
            name='id',
            field=models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID'),
        ),
    ]
