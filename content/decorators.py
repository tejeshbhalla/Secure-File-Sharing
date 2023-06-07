from files.utils import get_user,get_user_from_tenant


def get_user(func):
    def wrapper(self, request, *args, **kwargs):
        user = get_user_from_tenant(request)
        kwargs['user'] = user
        return func(self, request, *args, **kwargs)
    return wrapper

def get_tenant(func):
    def wrapper(self, request, *args, **kwargs):
        tenant = get_tenant(request)
        kwargs['tenant'] = tenant
        return func(self, request, *args, **kwargs)
    return wrapper 