from django.core.cache import cache
from django.utils.cache import get_cache_key
from django.utils.deprecation import MiddlewareMixin
from django.conf import settings
from django.http import HttpResponse
from django.core.exceptions import ValidationError
from django.urls import resolve
from collections import defaultdict
import time



class RateThrottle(MiddlewareMixin):
    def __init__(self, get_response=None):
        self.get_response = get_response
        self.throttle_rates = getattr(settings, 'THROTTLE_RATES', {})
        self.cache = cache

    def process_request(self, request):
        self.parse_rate()
        if not self.should_be_throttled(request):
            return None
        return self.throttled_response(request)

    def parse_rate(self):
        self.rates = defaultdict(lambda: (None, None))
        for key, value in self.throttle_rates.items():
            try:
                rate, interval = value.split('/')
                self.rates[key] = (int(rate), int(interval))
            except (ValueError, TypeError):
                pass

    def should_be_throttled(self, request):
        view_func = resolve(request.path_info).func
        if hasattr(view_func, 'throttle_scope'):
            self.scope = view_func.throttle_scope
            self.rate, self.interval = self.rates.get(self.scope, (None, None))
            if self.rate is None or self.interval is None:
                return False
            self.history_key = get_cache_key(request)
            self.history = self.cache.get(self.history_key, [])
            self.now = time.time()
            self.history = [x for x in self.history if x > self.now - self.interval]
            if len(self.history) >= self.rate:
                return True
        return False

    def throttled_response(self, request):
        return HttpResponse(status=429)



