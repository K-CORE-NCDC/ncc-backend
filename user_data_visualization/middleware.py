import json
from django.conf import settings
from django.db import connections
from user_data_visualization.models import UserDataProjects

def make_new_database_connection(project_id):
    project = UserDataProjects.objects.get(id=project_id)
    default = {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": project.sql_path,
    }
    connections.databases[str(project_id)] = default
    settings.DB = str(project_id)


class MiddlewareUserData:
    def __init__(self, get_response=None):
        self.get_response = get_response
        super().__init__()

    def __call__(self, request):
        file_name = request.FILES.get("file")
        if request.META["REQUEST_METHOD"] == "POST" and file_name is None:
            try:
                request_body = json.loads(request.body)
                project_id = request_body.get("project_id")
                if project_id is not None:
                    make_new_database_connection(project_id)
                else:
                    settings.DB = "default"
            except:
                pass
        else:
            settings.DB = "default"
        response = None
        if hasattr(self, "process_request"):
            response = self.process_request(request)

        response = response or self.get_response(request)

        if hasattr(self, "process_response"):
            response = self.process_response(request, response)
        return response
