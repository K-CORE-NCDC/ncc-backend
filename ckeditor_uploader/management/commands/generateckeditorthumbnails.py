import os

from django.conf import settings
from django.core.management.base import BaseCommand

from ckeditor_uploader.backends import get_backend
from ckeditor_uploader.utils import get_thumb_filename
from ckeditor_uploader.views import get_all_files


class Command(BaseCommand):
    """
    Creates thumbnail files for the CKEditor file image browser.
    Useful if starting to use django-ckeditor with existing images.
    """

    def handle(self, *args, **options):
        if getattr(settings, "CKEDITOR_IMAGE_BACKEND", None):
            backend = get_backend()
            for image in get_all_files():
                if not self._thumbnail_exists(image):
                    self.stdout.write("Creating thumbnail for %s" % image)
                    try:
                        backend.create_thumbnail(image)
                    except Exception as e:
                        self.stdout.write(f"Couldn't create thumbnail for {image}: {e}")
            self.stdout.write("Finished")
        else:
            self.stdout.write("No thumbnail backend is enabled")

    def _thumbnail_exists(self, image_path):
        thumb_path = self._to_absolute_path(get_thumb_filename(image_path))
        return os.path.isfile(thumb_path)

    @staticmethod
    def _to_absolute_path(image_path):
        return os.path.join(settings.MEDIA_ROOT, image_path)
