from django.contrib import admin
from django.urls import re_path as url
from django.urls import include,path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from files.views import Verify_Token
from rest_framework_swagger.views import get_swagger_view


schema_view = get_swagger_view(title='Pastebin API')

urlpatterns = [
    path('api/cghjklop/', admin.site.urls),
    path("api/auth/",include('files.urls',namespace='files_app')),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/token/verify/<str:token>',Verify_Token.as_view(), name='token_verify'),
    path('api/content/',include('content.urls',namespace='content_app'),),
    path('api/sync/',include('ftp.urls',namespace='sync_app'),),
    url(r'^$', schema_view),
]
