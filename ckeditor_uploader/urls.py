from django.contrib.admin.views.decorators import staff_member_required
from django.urls import re_path, path
from django.views.decorators.cache import never_cache

from . import views


urlpatterns = [
    re_path(r"^upload/", views.upload, name="ckeditor_upload"),
    path(
        "browse/<str:typ>/",
        never_cache(staff_member_required(views.browse)),
        name="ckeditor_browse",
    ),
]
