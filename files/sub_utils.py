from .models import Tenant
from .models import NewUser
from .utils import get_user

def get_hostname(request):
   return request.get_host().split(':')[0].lower() 


def get_tenant(request):
    subdomain=request.GET['tenant']
    return Tenant.objects.get(subdomain=subdomain)



def get_user_from_tenant(request):
    tenant=get_tenant(request)
    user=get_user(request)
    user=NewUser.objects.filter(tenant=tenant).filter(username=user).first()
    return user