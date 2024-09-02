# Generated by Django 5.0.6 on 2024-08-30 13:39

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('Verify', '0001_initial'),
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='usermodel',
            options={},
        ),
        migrations.AddField(
            model_name='usermodel',
            name='reset_password_token',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
        migrations.AddField(
            model_name='usermodel',
            name='reset_password_token_expiry',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddConstraint(
            model_name='usermodel',
            constraint=models.UniqueConstraint(fields=('email',), name='unique_email'),
        ),
        migrations.AddConstraint(
            model_name='usermodel',
            constraint=models.UniqueConstraint(fields=('phone_number',), name='unique_phone_number'),
        ),
    ]
