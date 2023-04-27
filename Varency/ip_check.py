from django.core.cache import cache
from django.http import HttpResponseForbidden
import requests

class IPCheckMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):

        # Get the IP address of the client making the request
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')

        # Check if the IP information is in the cache
        cache_key = f"ip_info_{ip}"
        ip_info = cache.get(cache_key)

        if ip_info is None:
            # If the IP information is not in the cache, fetch it from the API
            url=f'http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query'
            r=requests.get(url)
            if r.status_code==200:
                ip_info=r.json()
                # Cache the IP information for 1 hour
                cache.set(cache_key, ip_info, 3600)

        # Check if the IP address is from a proxy or hosting server
        if ip_info['proxy']:
            return HttpResponseForbidden('Invalid Request',status=405)

        # If the IP information is in the cache and it's not from a proxy or hosting server, proceed with the request
        response = self.get_response(request)
        return response