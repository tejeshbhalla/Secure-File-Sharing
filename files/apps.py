from django.apps import AppConfig


class FilesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'files'

    def ready(self):
        print("Starting Scheduler")
        from .token_schedule import cleaner
        import content.signals
        cleaner.start()

