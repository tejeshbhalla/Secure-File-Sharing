from django.http import HttpResponseBadRequest
from fnmatch import fnmatch
from Varency.settings import ALLOWED_REFERERS


class RefererMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.allowed_referers = ALLOWED_REFERERS

    def __call__(self, request):
        if 'auth' in request.path and 'wopi' in request.path:
             response = self.get_response(request)
             return response

        referer = request.META.get('HTTP_REFERER')
        
        if not referer or not any(fnmatch(referer, r) for r in self.allowed_referers):
            return HttpResponseBadRequest('Invalid Request')
        response = self.get_response(request)
        return response
