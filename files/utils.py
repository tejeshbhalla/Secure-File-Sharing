from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
import datetime 
import jwt
from Varency.settings import SECRET_KEY,FRONT_END_URL,EMAIL_HOST_USER
import string
import random
from asgiref.sync import sync_to_async
import boto3
from boto.s3.connection import S3Connection
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags






def no_of_recovery_days(file):
    tenant=file.owner.tenant
    plan_type=tenant.plan_type
    if plan_type=='Basic':
        return tenant.basic_plan.max_recovery_days
    if plan_type=='Premium':
        return tenant.premium_plan.max_recovery_days
    return 7

def file_size(tenant,file): 
    plan_type=tenant.plan_type
    if plan_type=='Basic':
        limit = tenant.basic_plan.max_upload_file_size*1024 * 1024 * 1024
        if file.content.size > limit:
            return True
    if plan_type=='Premium':
        limit = tenant.premium_plan.max_upload_file_size*1024 * 1024 * 1024
        if file.content.size > limit:
            return True
    return True


def send_email(email,token,request,type,message=None):
    if type=='activate':     
         link=f'http://{message}.{FRONT_END_URL}Authentication/activation/{token}'
         message=f'Please click/open the following link in your browser to activate your account {link}'
         html_content=render_to_string(r"activate.html",{"link":link,'title':'activate account','message':message})

    if type=='reset':
         link=f'http://{message}.{FRONT_END_URL}Authentication/resetpassword/{token}'
         message=f'Please click/open the following link in your browser to reset your account {link}'
         html_content=render_to_string(r"activate.html",{'link':link,'title':'reset account','message':message})
    if type=='otp':
        message=f"Your verification code for logging in is {token}"
        code=token
        html_content=render_to_string(r"2fa.html",{'otp':code,'name':email.split('@')[0]})

    text_content=strip_tags(html_content)
    email=EmailMultiAlternatives('Mail from Varency',text_content,EMAIL_HOST_USER,[email])
    email.attach_alternative(html_content,'text/html')
    email.send()


def send_email_info(email,name,tenant):
    text_content=f'New Registeration email,name,tenant:{email,name,tenant}'
    email=EmailMultiAlternatives('Mail from Varency',text_content,EMAIL_HOST_USER,['info@varency.com'])
    email.send()



def get_user(request,token=''):
    if len(token)==0:
        auth=request.headers.get('Authorization').split(' ')
        token=auth[1]
    payload=jwt.decode(token,SECRET_KEY,algorithms=['HS256',])
    username=payload.get('username')
    return username

def get_token(request):
    auth=request.headers.get('Authorization').split(' ')
    token=auth[1]
    return token


def id_generator(model,size=6, chars=string.ascii_uppercase + string.digits+string.ascii_lowercase):
    otp=''.join(random.choice(chars) for _ in range(size))
    while True:
        if len(model.objects.filter(otp=otp))>0:
            otp=''.join(random.choice(chars) for _ in range(size))
        else:
            break

    return otp

def id_generator_2(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))





def user_available(tenant):
    plan_type=tenant.plan_type
    total_user=tenant.no_of_users
    if plan_type=='Basic':
        if total_user+1>tenant.basic_plan.no_of_users:
            return False
    elif plan_type=='Premium':
        if total_user+1>tenant.premium_plan.no_of_users:
            return False
    return True
