import os
from datetime import datetime
from logging.handlers import TimedRotatingFileHandler
from django.apps import AppConfig
from django.conf import settings



class UserDataVisualizationConfig(AppConfig):
    name = "user_data_visualization"

    def ready(self):
        print('starting scheduler....')
        from .user_data_visualization_scheduler import delete_files_scheduler
        delete_files_scheduler.start()

class DynamicLogFileHandler(TimedRotatingFileHandler):
    def __init__(self, *args, **kwargs):
        # Path format using MEDIA_ROOT or dedicated environment variable
        log_file_path = os.path.join(
            settings.MEDIA_ROOT,
            'log_files',
            f'{datetime.now().strftime("%d-%m-%Y")}_Exceptions.log'
        )
        super().__init__(log_file_path, *args, **kwargs)
