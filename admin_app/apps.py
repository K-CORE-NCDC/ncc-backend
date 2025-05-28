from django.apps import AppConfig



class AdminAppConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "admin_app"

    # def ready(self):
    #     print('Starting stats scheduler...')
    #     from .stats_scheduler import start
    #     start()
