from datetime import datetime
from rest_framework.authentication import get_authorization_header,BaseAuthentication
from rest_framework import exceptions
import jwt
from django.conf import settings
from .models import NewUser,BlacklistedToken
from rest_framework.permissions import BasePermission
from rest_framework.response import Response
from rest_framework import status

class JWTauthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header=get_authorization_header(request)
        auth_data=auth_header.decode('utf-8')
        auth_token=auth_data.split(' ')
        if len(auth_token)!=2:
            raise exceptions.AuthenticationFailed("Error incorrect token")
        token=auth_token[1]
        token_bt=BlacklistedToken.objects.filter(token=token).first()
        if token_bt:
            raise exceptions.AuthenticationFailed("Token Expired")
        try:
            payload=jwt.decode(token,settings.SECRET_KEY,algorithms=['HS256',])

            username=payload.get('username')
            user=NewUser.objects.get(username=username)
            if user.is_active:
                if user.is_activated:
                    user.last_access=datetime.now()
                    return (user,token)
                else:
                    raise exceptions.AuthenticationFailed("Account not activated")
            else:
                    raise exceptions.AuthenticationFailed("Account has been suspended")

        except NewUser.DoesNotExist:
            raise exceptions.AuthenticationFailed("User does not exist")

        except Exception as e:
            raise exceptions.AuthenticationFailed(f"{e}")



