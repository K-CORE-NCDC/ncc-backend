from django.contrib.auth import get_user_model
from django.contrib.sessions.models import Session
from django.http import HttpResponse
from rest_framework.request import Request as RestFrameworkRequest
from rest_framework.views import APIView

User = get_user_model()


class SessionVerificationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        session_id = request.COOKIES.get("sessionid")
        if session_id is not None:
            try:
                session = Session.objects.get(session_key=session_id)
                session_data = session.get_decoded()
                if session_data:
                    request.session_valid = True
                else:
                    return HttpResponse(status=204)

            except Session.DoesNotExist:
                return HttpResponse(status=204)
        elif session_id is None:
            pass
        response = self.get_response(request)
        return response


class MyMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        drf_request: RestFrameworkRequest = APIView().initialize_request(request)
        return self.get_response(request)
