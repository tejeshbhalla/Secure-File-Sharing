from django.core.cache import cache
from django.http import HttpResponseForbidden
import requests

class IPCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Define rate limit variables
        rate_limit = 100
        rate_period = 60  # in seconds

        # Get the IP address of the client making the request
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        # Check if the IP address has exceeded the rate limit
        url=f'http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query'
        r=requests.get(url)
        if r.status_code==200:
            data=r.json()
            if data['proxy'] or data['hosting']:
                return HttpResponseForbidden('Invalid Request',status=405)
            else:
                response = self.get_response(request)
                return response
        return HttpResponseForbidden('Invalid Request',status=405)
