# Generated by Django 3.1.8 on 2021-04-09 19:27

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('custusers', '0004_auto_20201025_1726'),
    ]

    operations = [
        migrations.AlterField(
            model_name='historicaluser',
            name='first_name',
            field=models.CharField(blank=True, max_length=150, verbose_name='first name'),
        ),
        migrations.AlterField(
            model_name='user',
            name='first_name',
            field=models.CharField(blank=True, max_length=150, verbose_name='first name'),
        ),
    ]
