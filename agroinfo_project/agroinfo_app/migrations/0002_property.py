# Generated by Django 5.0.6 on 2024-05-13 11:35

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agroinfo_app', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Property',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('endereco', models.CharField(max_length=100)),
                ('distritooulocalidade', models.CharField(max_length=100)),
                ('numero', models.CharField(max_length=100)),
                ('cidade', models.CharField(max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('owner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
