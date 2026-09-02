from __future__ import annotations
import os
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

class Command(BaseCommand):
    help = 'Create or update the configured deployment administrator.'
    def handle(self, *args, **options):
        username = os.getenv('ADMIN_USERNAME', '').strip()
        email = os.getenv('ADMIN_EMAIL', '').strip()
        password = os.getenv('ADMIN_PASSWORD', '')
        if not username or not email or not password:
            raise CommandError('ADMIN_USERNAME, ADMIN_EMAIL and ADMIN_PASSWORD are required.')
        user_model = get_user_model()
        user, created = user_model.objects.get_or_create(username=username, defaults={'email': email})
        user.email = email
        user.is_staff = True
        user.is_superuser = True
        user.is_active = True
        user.set_password(password)
        user.save()
        self.stdout.write(self.style.SUCCESS('Admin user ' + ('created' if created else 'updated') + '.'))
