from django.core.cache import cache
from django.http import HttpResponseForbidden

class RateLimitMiddleware:
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
        key = f'rate_limit:{ip}'
        count = cache.get(key, 0)
        print(count)
        if count >= rate_limit:
            return HttpResponseForbidden('Rate limit exceeded',status=405)

        # Increment the request count and set the cache key with the new count
        count += 1
        cache.set(key, count, rate_period)

        # Call the next middleware or view
        response = self.get_response(request)
        return response
