from datetime import datetime
from django.contrib.auth import get_user_model
from django.db import models
from django.utils.text import slugify

User = get_user_model()

# Create your models here.


class MailVerifyDetails(models.Model):
    email_id = models.EmailField(max_length=254, unique=True)
    otp_recieved_at = models.TimeField(
        auto_now=False, auto_now_add=False, default=datetime.now, blank=True
    )
    otp = models.CharField(max_length=255, default=None)
    created_on = models.DateTimeField(auto_now_add=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True, blank=True)


class CommunityManagementNotice(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    writer = models.CharField(max_length=125, blank=True, null=True, default=None)
    title = models.TextField(null=True, blank=True, default=None)
    content = models.TextField(null=True, blank=True, default=None)
    url_slug = models.SlugField(max_length=255, null=True, unique=True, default="")
    is_active = models.BooleanField(default=False)
    created_on = models.DateTimeField(auto_now_add=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True, blank=True)

    def save(self, *args, **kwargs):
        self.url_slug = self.url_slug or slugify(self.title)
        super().save(*args, **kwargs)


class CommunityManagementFaq(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    writer = models.CharField(max_length=125, blank=True, null=True, default=None)
    title = models.TextField(null=True, blank=True, default=None)
    content = models.TextField(null=True, blank=True, default=None)
    url_slug = models.SlugField(max_length=255, unique=True, default="")
    created_on = models.DateTimeField(auto_now_add=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True, blank=True)

    def save(self, *args, **kwargs):
        self.url_slug = self.url_slug or slugify(self.title)
        super().save(*args, **kwargs)


class CommunityManagementQnA(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    writer = models.CharField(max_length=125, blank=True, null=True, default=None)
    title = models.TextField(null=True, blank=True, default=None)
    content = models.TextField(null=True, blank=True, default=None)
    url_slug = models.SlugField(max_length=255, unique=True, default="")
    created_on = models.DateTimeField(auto_now_add=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True, blank=True)

    def save(self, *args, **kwargs):
        self.url_slug = self.url_slug or slugify(self.title)
        super().save(*args, **kwargs)
