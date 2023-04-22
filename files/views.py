from content.utils import get_client_ip,download_url_generate_sas,create_media_jwt
from files.sub_utils import get_tenant, get_user_from_tenant
from rest_framework.views import APIView
from rest_framework.response import Response
from .serializers import CreateGroupSerializer, DetailGroupSerializer, Logs_Serializer, Notification_Serializer, RegisterUser, TenantSerializer, UserSerializer, WorkSerializer
from rest_framework import status
from .models import Group_Permissions, NewUser,BlacklistedToken, Notifications,Otp_Token, People_Groups, User_logs,Tenant
from rest_framework.permissions import IsAuthenticated
from .jwt_utils import  JWTauthentication
import jwt 
from django.conf import settings
from .utils import  id_generator_2, send_email, user_available,send_email_info
from .tasks import send_bulk_email
import datetime 
from .utils import get_user,id_generator
from annoying.functions import get_object_or_None
import pytz
from content.models import Files_Model,Folder, Internal_Share, Link_Model,Internal_Share_Folders
import mimetypes
from django.http import HttpResponse
from django.core.files.base import ContentFile
from django.utils import timezone
import gevent

# Create your views here.
class UserView(APIView):
    """
    Return Details about a sepecific user
    """
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        user=get_user_from_tenant(request)
        tenant=get_tenant(request)
        data={"name":user.name,"username":user.username,"email":user.email,"is_admin":user.is_admin,'phone_number':user.phone_number,'permissions':{'two_factor':user.two_factor_activated},"domain":tenant.subdomain}
        return Response(data,status=status.HTTP_200_OK)



class RegisterView(APIView):
    """
    Register Admin User
    """
    def post(self, request, *args, **kwargs):
        try:
            serializers=RegisterUser(data=request.data)
            tenant=get_tenant(request)
            if serializers.is_valid():
                serializers.save(serializers.validated_data,tenant)
                email=serializers.validated_data['email']
                user=NewUser.objects.get(email=email)

                send_email(email,user.token('activate'),request,type='activate',message=tenant.subdomain)
                send_email_info(email,user.name,user.tenant.subdomain)
                return Response(data=serializers.data, status=status.HTTP_201_CREATED)

            return Response(data=serializers.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            
            return Response(data="error server",status=status.HTTP_400_BAD_REQUEST)

class Create_Tenant(APIView):
    """
    Create a tenant
    """
    def post(self,request,*args,**kwargs):
        serializers=TenantSerializer(data=request.data)
        if serializers.is_valid():
            serializers.save(serializers.validated_data)
            return Response(data=serializers.data, status=status.HTTP_201_CREATED)

        return Response(data=serializers.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyTenant(APIView):
    def post(self,request,*args,**kwargs):
        try:
            tenant=request.data['subdomain']
            tenant=Tenant.objects.filter(subdomain=tenant).first()
            if not tenant:
                return Response(data={'message':'tenant does not exist'},status=status.HTTP_400_BAD_REQUEST)
            if tenant:
                return Response(data={'message':'tenant exist'},status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message':f'{e}'},status=status.HTTP_400_BAD_REQUEST)



class LoginView(APIView):
    def post(self, request, *args, **kwargs):
        try:
            tenant=get_tenant(request)
            email=request.data.get('email',None)
            password=request.data.get("password",None)
            if email==None or password==None:
                return Response(data={'message':'invalid query no email or password'}, status=status.HTTP_400_BAD_REQUEST)
            obj=NewUser.objects.filter(tenant=tenant).get(email=email)
            if not obj.is_activated:
                return Response(data={'message':'Kindly activate your account before logging in'},status=status.HTTP_400_BAD_REQUEST)
            if not obj.is_active:
                return Response(data={'message':'Account suspended'},status=status.HTTP_400_BAD_REQUEST)
            if obj.check_password(password):
                if obj.two_factor_activated:
                    Otp_Token.objects.filter(user=obj).all().delete()
                    otp=id_generator(Otp_Token)
                    model_otp=Otp_Token(otp=otp,user=obj,time_expired=timezone.now()+datetime.timedelta(minutes=5))
                    model_otp.save()
                    send_email(obj.email,token=otp,request=request,type='otp')
                    return Response(data={"message":"Otp send on email"},status=status.HTTP_200_OK)

                else:
                    d={'username':obj.username, 'token':obj.token('login')}
                    return Response(data=d, status=status.HTTP_202_ACCEPTED)
            else:
                return Response(data={'message':'Incorrect credentials'}, status=status.HTTP_400_BAD_REQUEST)

        except Tenant.DoesNotExist:
            return Response(data={'message':"Tenant not Found"},status=status.HTTP_400_BAD_REQUEST)
        except NewUser.DoesNotExist:
            return Response(data={'message':"User not Found"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            
            return Response(data={"message":f'check credentials {str(e)}'}, status=status.HTTP_400_BAD_REQUEST)


class TokenVerifyView(APIView):
    def get(self, request,token):
        try :
            tenant=get_tenant(request)
            payload=jwt.decode(token,settings.SECRET_KEY,algorithms=['HS256',])
            if payload['aim']!='activate':
                return Response(data={'message':'token invalid try again'},status=status.HTTP_400_BAD_REQUEST)
            id=payload.get('id')
            user=NewUser.objects.filter(tenant=tenant).filter(id=id).first()
            if user:
                if user.black_listed:
                    token_bt=BlacklistedToken.objects.filter(token=token)
                    if token_bt:
                        return Response(data={'message':'token expired'},status=status.HTTP_400_BAD_REQUEST)
                user.is_activated=True
                b_t=BlacklistedToken(token=token,time_expired=datetime.datetime.fromtimestamp(payload['exp']),user=user)
                b_t.save()
                user.save()
                return Response(data={'message':'Successfully activated account '})
            else:
                return Response(data={'message':'Failure User not found'}, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(data={'message':f'{str(e)}'}, status=status.HTTP_400_BAD_REQUEST)


class ForgotPassword(APIView):
    def post(self,request, *args, **kwargs):
        user=None
        try:
                tenant=get_tenant(request)
                email=request.data['email']
                if email !=None:
                    user=NewUser.objects.filter(tenant=tenant).get(email=email)
                if not user:
                    return Response(data={'message':'User not found'}, status=status.HTTP_400_BAD_REQUEST)
                email=user.email
                token=user.token("reset_password")
                print(token)
                send_email(email,token,request,'reset',message=tenant.subdomain)
                return Response(data={'message':'reset email sent'}, status=status.HTTP_200_OK)
        except Exception as e:
                
                return Response(data={'message':f"{e} failed"},status=status.HTTP_400_BAD_REQUEST)



class ResetPassword(APIView):
    def post(self, request,token):
        try :
            payload=jwt.decode(token,settings.SECRET_KEY,algorithms=['HS256',])
            tenant=get_tenant(request)
            if payload['aim']!='reset_password':
                return Response(data={"message":"failed invalid token"},status=status.HTTP_400_BAD_REQUEST)
            id=payload.get('id')
            user=NewUser.objects.filter(tenant=tenant).filter(id=id).first()
            if user:
                if user.black_listed:
                    token_bt=BlacklistedToken.objects.filter(token=token).first()
                    if token_bt:
                        return Response(data={'message':'token expired'},status=status.HTTP_400_BAD_REQUEST)
            password=request.data.get('password')
            if not password or len(password)<6:
                return Response(data={"message":"entered password must be at least 6 characters"},status=status.HTTP_400_BAD_REQUEST)
            if user:
                user.set_password(password)
                b_t=BlacklistedToken(token=token,time_expired=datetime.datetime.fromtimestamp(payload['exp']))
                b_t.save()
                #b_t.user.set([user])
                user.save()
                return Response(data={'message':'password reset successful'},status=status.HTTP_200_OK)
            else:
                return Response(data={'message':"Not found user"})
        except Exception as e:
            return Response(data={'message':f'{e}'}, status=status.HTTP_400_BAD_REQUEST)


class Change_Password(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    def post(self,request,*args,**kwargs):
        try:
            if 'old_password' not in request.data:
                return Response({"message":"old_password not sent"},status=status.HTTP_400_BAD_REQUEST)
            if 'password' not in request.data:
                return Response({"message":"old_password not sent"},status=status.HTTP_400_BAD_REQUEST)

            user=get_user_from_tenant(request)
            if user.check_password(request.data['old_password']):
                user.set_password(request.data['password'])
                user.save()
                return Response({"message":"Password changed successfully"},status=status.HTTP_200_OK)
            else:
                return Response({"message":"Incorrect password"},status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({"message":str(e)},status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    def get(self, request, *args, **kwargs):
        try:
            user=get_user_from_tenant(request)
            arr=request.headers.get('Authorization').split(' ')
            if len(arr)<2:
                return Response(data={'failed logout invalid token'}, status=status.HTTP_400_BAD_REQUEST)
        
            token=arr[1]
            payload=jwt.decode(token,settings.SECRET_KEY,algorithms=['HS256',])
            username=payload.get('username')
            tenant=get_tenant(request)
            user=NewUser.objects.filter(tenant=tenant).filter(username=username).first()
            if user:
                b_t=BlacklistedToken(token=token,time_expired=datetime.datetime.fromtimestamp(payload['exp']))
                b_t.save()
                #b_t.user.set([user])
                #b_t.save()
            return Response(data={'message':'success'},status=status.HTTP_200_OK)
                
        except Exception as e:
            
            return Response(data={f'{e}'},status=status.HTTP_400_BAD_REQUEST)






class ResendActivation(APIView):
    def get(self, request, email):
        try:
            tenant=get_tenant(request)
            user=NewUser.objects.filter(tenant=tenant).filter(email=email).first()
            send_email(user.email,user.token('activate'),request,type='activate',message=tenant.subdomain)
            return Response(data={"message":"link sent"}, status=status.HTTP_201_CREATED)
        except Exception as e:

            return Response(data={"message":f'{e}'}, status=status.HTTP_400_BAD_REQUEST)




class Otp_verify_view(APIView):
    def post(self,request):
        try:
            if 'otp' not in request.data:
                return Response(data={"message":"otp not in data"},status=status.HTTP_400_BAD_REQUEST)
            if 'email' not in request.data:
                return Response(data={"message":"email not in data"},status=status.HTTP_400_BAD_REQUEST)
            tenant=get_tenant(request)
            user=NewUser.objects.filter(tenant=tenant).filter(email=request.data['email']).first()
            otp_model=user.otps.all().first()
            utc=pytz.utc
            if otp_model.otp==request.data['otp']:
                if otp_model.time_expired<utc.localize(timezone.now()):
                   
                    return Response(data={"message":"otp expired"},status=status.HTTP_400_BAD_REQUEST)
                d={'username':user.username, 'token':user.token('login')}
            
                #here
                return Response(data=d, status=status.HTTP_202_ACCEPTED)
            else:
                return Response(data={"message":"otp incorrect"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)



class Resend_otp(APIView):
    def post(self,request,*args,**kwargs):
        try:
            if 'email' not in request.data:
                return Response(data={"message":"email not in data"},status=status.HTTP_400_BAD_REQUEST)
            tenant=get_tenant(request)
            user=NewUser.objects.filter(tenant=tenant).filter(email=request.data['email']).first()
            otp_obj=user.otps.all().first()
            if not otp_obj:
                otp_obj=Otp_Token(user=user)
            otp_obj.otp=id_generator(Otp_Token)
            otp_obj.time_expired=timezone.now()+datetime.timedelta(minutes=5)
            otp_obj.save()
            send_email(user.email,token=otp_obj.otp,request='req',type='otp')
            return Response(data={"message":"otp sent on email"},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)

class People_Group_Create(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    #ik this function is shit , absolute ass credits- mrshadowface
    def post(self,request,*args,**kwargs):
        try:
            owner=get_user_from_tenant(request)
            tenant=get_tenant(request)
            request.data['owner']=owner
            sz=CreateGroupSerializer(data=request.data)
            if sz.is_valid():
                if 'user_list' not in request.data:
                    return Response("user_list not in data",status=status.HTTP_400_BAD_REQUEST)
                for i in request.data['user_list']:
                    user=NewUser.objects.filter(tenant=tenant).filter(email=i).first()
                    if not user:
                        return Response(data={'message':f'User not found'},status=status.HTTP_400_BAD_REQUEST)
                    if user==owner:
                        return Response(data={"message":f"Can't add yourself"},status=status.HTTP_400_BAD_REQUEST)
                    obj=sz.create(sz.validated_data)
                    per=Group_Permissions(group=obj,user=user,is_admin=False,has_read=True,can_add_delete_content=True)
                    per.save()

                return Response(data={"message":{"Group created successfully"}},status=status.HTTP_200_OK)
            return Response(data=sz.errors,status=status.HTTP_400_BAD_REQUEST)
        except NewUser.DoesNotExist:
            obj.delete()
            return Response(data={'message':{'user email does not exist'}},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)


    def delete(self,request):
        try:
            user=get_user_from_tenant(request)
            if 'url_hash' not in request.data:
                return Response(data={"message":"url hash not in data"},status=status.HTTP_400_BAD_REQUEST)
            obj=People_Groups.objects.filter(group_hash__in=request.data['url_hash'],owner=user)
            obj.delete()
            return Response(data={"message":"successfully deleted"},status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)


    def put(self,request,link_hash,*args,**kwargs):
        try:
            user=get_user_from_tenant(request)
            request.data['owner']=user
            obj=People_Groups.objects.filter(group_hash=link_hash).first()
            per=Group_Permissions.objects.filter(group=obj,user=user).first()
            if obj.owner==user or per.is_admin:
                sz=CreateGroupSerializer(data=request.data)
                if sz.is_valid():
                    sz.validated_data['group']=obj
                    obj=sz.update(sz.validated_data)
                    return Response(data={"message":"successfully updated"},status=status.HTTP_200_OK)
                return Response(data=sz.errors,status=status.HTTP_400_BAD_REQUEST)
            return Response(data={"message":"Unauthorized"},status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)



class User_to_Group(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    
    def post(self,request,urlhash):
        try:
            grp=People_Groups.objects.get(group_hash=urlhash)
            if 'user_list' not in request.data:
                return Response(data={'message':"user_list not in data"},status=status.HTTP_400_BAD_REQUEST) 
            user_list=request.data['user_list']
            tenant=get_tenant(request)
            all_users=NewUser.objects.filter(tenant=tenant).filter(email__in=user_list)
            if len(all_users)==0:
                return Response({'message':'no user found'},status=status.HTTP_400_BAD_REQUEST)
            for i in all_users:
            
                if get_object_or_None(Group_Permissions,group=grp,user=i):
                    return Response(data={"message":'{i.email} already in group'},status=status.HTTP_400_BAD_REQUEST)
                grp_per=Group_Permissions(group=grp,user=i)
                grp_per.save()
            return Response(data={"message":'success'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={'message':{e}},status=status.HTTP_400_BAD_REQUEST)
    def delete(self,request,urlhash):
        try:
            grp=People_Groups.objects.get(group_hash=urlhash)
            user=get_user_from_tenant(request)
            tenant=get_tenant(request)
            if 'user_list' not in request.data:
                return Response(data={'message':"user_list not in data"},status=status.HTTP_400_BAD_REQUEST) 
            user_list=request.data['user_list']
            all_users=NewUser.objects.filter(tenant=tenant).filter(email__in=user_list)
            if len(all_users)==0:
                return Response({'message':'no user found'},status=status.HTTP_400_BAD_REQUEST)
            user_per=get_object_or_None(Group_Permissions,group=grp,user=user)
            if not user_per.is_admin or grp.owner!=user:
                return Response({"message":'unauthorized'},status=status.HTTP_400_BAD_REQUEST)
            for i in all_users:
                user_mem=get_object_or_None(Group_Permissions,group=grp,user=i)
                if not user_mem :
                    return Response(data={"message":'{i.email} not in group'})
                user_mem.delete()
            return Response(data={"message":'success'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={'message':{e}},status=status.HTTP_400_BAD_REQUEST)

class Add_Files_Folder_Group(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def post(self,request,*args,**kwargs):
        try:
            if 'folder_hash' not in request.data or 'file_hash' not in request.data or 'group_hash' not in request.data:
                    return Response(data={"message":"folder_hash or file_hash or group_hash not in data"},status=status.HTTP_400_BAD_REQUEST)
            for i in request.data['group_hash']:
                grp=People_Groups.objects.get(group_hash=i)
                user=get_user_from_tenant(request)
                permissions=Group_Permissions.objects.filter(user=user,group=grp).first()
                if permissions.can_add_delete_content or permissions.is_admin:
                    files=Files_Model.objects.filter(urlhash__in=request.data['file_hash'],owner=user)
                    folders=Folder.objects.filter(urlhash__in=request.data['folder_hash'],owner=user)
                    grp.files.add(*files)
                    grp.folders.add(*folders)
                    grp.save()
                else:
                    return Response(data={"message":"Don't have privelages"},status=status.HTTP_400_BAD_REQUEST)
            return Response(data={"message":"successfully added content"},status=status.HTTP_200_OK)

        except Exception as e:
            print(e)
            return Response(data={'message':f"{e}"},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,urlhash):
        try:
            grp=People_Groups.objects.get(group_hash=urlhash)
            user=get_user_from_tenant(request)
            permissions=Group_Permissions.objects.filter(user=user,group=grp).first()
            if permissions.can_add_delete_content or permissions.is_admin:

                if 'folder_hash' not in request.data or 'file_hash' not in request.data:
                    return Response(data={"message":"folder_hash or file_hash not in data"},status=status.HTTP_400_BAD_REQUEST)
                files=Files_Model.objects.filter(urlhash__in=request.data['file_hash'])
                folders=Folder.objects.filter(urlhash__in=request.data['folder_hash'])

                grp.files.remove(*files)
                grp.save()
                grp.folders.remove(*folders)
                grp.save()
                return Response(data={"message":"successfully removed content"},status=status.HTTP_200_OK)

            else:
                return Response(data={"message":"Don't have privelages"},status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response(data={'message':f"{e}"},status=status.HTTP_400_BAD_REQUEST)



class Update_Users_In_Group(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def post(self,request,urlhash):
        try:
            grp=People_Groups.objects.get(group_hash=urlhash)
            user=get_user_from_tenant(request)
            tenant=get_tenant(request)
            if 'user_data' not in request.data:
                return Response(data={"message":'email not in data'},status=status.HTTP_400_BAD_REQUEST)
            per1=Group_Permissions.objects.filter(group=grp,user=user).first()
            if per1.is_admin:
                for i in request.data['user_data']:
                    email=i['email']
                    user_=NewUser.objects.filter(tenant=tenant).filter(email=email).first()
                    per2=Group_Permissions.objects.filter(group=grp,user=user_).first()
                    is_admin=i['is_admin']
                    can_add_delete_content=i['can_add_delete_content']
                    can_share_content=i['can_share_content']
                    can_download_content=i['can_download_content']
                    is_proctored=i['is_proctored']
                    per2.is_admin=is_admin
                    per2.can_add_delete_content=can_add_delete_content
                    per2.can_share_content=can_share_content
                    per2.can_download_content=can_download_content
                    per2.is_proctored=is_proctored
                    per2.save()
                return Response(data={"message":'User permission changed'},status=status.HTTP_200_OK)
            return Response(data={"message":"Don't have privelages"},status=status.HTTP_400_BAD_REQUEST)

            
        except Exception as e:
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)



class Detail_User_Groups(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def get(self,request,*args, **kwargs):
        try:
            user=get_user_from_tenant(request)
            all_permissions=Group_Permissions.objects.filter(user=user).all()
            data=[]
            for i in all_permissions:
                grp=i.group
                is_owner=grp.owner==user
                is_admin=i.is_admin
                is_read=i.has_read
                can_add_delete_content=i.can_add_delete_content
                all_members_per=Group_Permissions.objects.filter(group=grp)
                all_members=[]
                for i in all_members_per:
                    is_owner_user=grp.owner==i.user
                    all_members.append({'username':i.user.username,'is_admin':i.is_admin,'can_share_content':i.can_share_content,'is_proctored':i.is_proctored,'can_download_content':i.can_download_content,'has_read':i.has_read,'can_add_delete_content':i.can_add_delete_content,'email':i.user.email,'is_owner':is_owner_user})

                d={'name':grp.name,'urlhash':grp.group_hash,'owner':grp.owner.username,'is_owner':is_owner,'is_read':is_read,'can_add_delete_content':can_add_delete_content,'members':all_members,'admin':is_admin,'description':grp.description,'created':grp.created,'is_favourite':i.is_favourite}

                data.append(d)
            return Response(data,status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)


class Group_Folder_Detail(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def get(self,request,group_hash, folder_hash):
        try:
            user=get_user_from_tenant(request)
            grp=People_Groups.objects.filter(group_hash=group_hash).first()
            per=Group_Permissions.objects.filter(group=grp,user=user).first()
            if folder_hash=='root':
                files=grp.files.all()
                folders=grp.folders.all()
                data={'files':[],'children':[],'parent_permissions':{'can_add_delete_content':per.can_add_delete_content,'has_read':per.has_read}}
                for j in folders:
                    data['children'].append({'urlhash':j.urlhash,'name':j.name,'owner':j.owner.username,'is_folder':True,'path':j.order_parent(),'hash_path':j.order_parent_urlhash(),'can_add_delete_content':per.can_add_delete_content,'has_read':per.has_read,
                'download_link':f'{settings.BACKEND_URL}api/content/folder_download/{create_media_jwt(i,get_client_ip(request))}' if per.can_download_content else None,'can_download_content':per.can_download_content})
                for i in files:
                    data['files'].append({'name':i.file_name,"url":f'{settings.BACKEND_URL}api/content/media/{create_media_jwt(i,get_client_ip(request))}','owner':i.owner.username,'urlhash':i.urlhash,'is_file':True,'date_created':i.date_uploaded,'size':i.filesize,'can_add_delete_content':per.can_add_delete_content,'has_read':per.has_read,'can_share':per.can_share_content,'can_download_content':per.can_download_content,
                                          'download_link':download_url_generate_sas(i,get_client_ip(request)) if per.can_download_content else None})
                return Response(data,status=status.HTTP_200_OK)
            data={'files':[],'children':[],'parent_permissions':{'can_add_delete_content':per.can_add_delete_content,'has_read':per.has_read}}
            folder=Folder.objects.get(urlhash=folder_hash)
            children=folder.children.all()
            files=folder.files.all()
            for j in children:
                data['children'].append({'urlhash':j.urlhash,'name':j.name,'owner':j.owner.username,'is_folder':True,'path':j.order_parent(),'hash_path':j.order_parent_urlhash(),'can_add_delete_content':per.can_add_delete_content,'has_read':per.has_read,
                                         'download_link':f'{settings.BACKEND_URL}api/content/folder_download/{create_media_jwt(i,get_client_ip(request))}' if per.can_download_content else None,'can_download_content':per.can_download_content})
            for i in files:
                data['files'].append({'name':i.file_name,"url":f'{settings.BACKEND_URL}api/content/media/{create_media_jwt(i,get_client_ip(request))}','owner':i.owner.username,'urlhash':i.urlhash,'is_file':True,'date_created':i.date_uploaded,'size':i.filesize,'can_add_delete_content':per.can_add_delete_content,'has_read':per.has_read,'can_share':per.can_share_content,'can_download_content':per.can_download_content,
                                      'download_link':download_url_generate_sas(i,get_client_ip(request)) if per.can_download_content else None})
            return Response(data,status=status.HTTP_200_OK)
        except Exception as e:
            
            return Response({"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)




class Update_User_Permissions(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def post(self,request,*args, **kwargs):
        try:
            user=get_user_from_tenant(request)
            if 'two_factor' not in request.data:
                return Response({"message":"two_factor not in data"},status=status.HTTP_400_BAD_REQUEST)
            user.two_factor_activated=request.data['two_factor']
            user.save()
            return Response({"message":"updated successfully"},status=status.HTTP_200_OK)
        except Exception as e:
            
            return Response({"message":str(e)},status=status.HTTP_400_BAD_REQUEST)


class View_Users(APIView):
    authentication_classes=[JWTauthentication]
    permissions=[IsAuthenticated]

    def get(self,request,*args,**kwargs):
        try:
            user=get_user_from_tenant(request)
            tenant=get_tenant(request)
            if user.is_admin:
                all_users=NewUser.objects.filter(tenant=tenant).all()
                sz=UserSerializer(all_users,many=True)
                return Response(sz.data,status=status.HTTP_200_OK)
            return Response({"message":"You don't have privelages to access this page"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"message":str(e)},status=status.HTTP_400_BAD_REQUEST)


class Admin_Edit_User_Details(APIView):
    authentication_classes=[JWTauthentication]
    permissions=[IsAuthenticated]

    def put(self,request,username):
        try:
            user=get_user_from_tenant(request)
            tenant=get_tenant(request)
            if user.is_admin:
                employee=NewUser.objects.filter(tenant=tenant).filter(username=username).first()
                change=False
                if employee and employee!=user:
                    if 'is_admin' in request.data:
                        employee.is_admin=request.data['is_admin']
                        change=True
                    if 'is_active' in request.data:
                        employee.is_active=request.data['is_active']
                        change=True
                    if change:
                        employee.save()
                        return Response(data={'message':'User suspended'},status=status.HTTP_200_OK)
                    elif change==False:
                        return Response(data={"message":"No changes implemented"},status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"message":f"{username} does not exist or can't suspend"},status=status.HTTP_400_BAD_REQUEST)
            return Response({"message":"You don't have privelages to access this page"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({"message":str(e)},status=status.HTTP_400_BAD_REQUEST)

class Admin_Delete_User(APIView):
    authentication_classes=[JWTauthentication]
    permissions=[IsAuthenticated]

    def delete(self,request,username):
        try:
            user=get_user_from_tenant(request)
            tenant=get_tenant(request)
            if user.is_admin:
                employee=NewUser.objects.filter(tenant=tenant).filter(username=username).first()
                change=False
                if employee:
                    employee.delete()
                    change=True
                    if change:
                        return Response(data={"message":f'{employee} successfully removed'},status=status.HTTP_200_OK)
                    elif change==False:
                        return Response(data={"message":"No changes implemented"},status=status.HTTP_400_BAD_REQUEST)
                else:
                    return Response({"message":f"{username} does not exixt"},status=status.HTTP_400_BAD_REQUEST)
            return Response({"message":"You don't have privelages to access this page"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            
            return Response({"message":str(e)},status=status.HTTP_400_BAD_REQUEST)


class AdminCreateUsers(APIView):
    ''' Admin user can bulk create user accounts using a csv
        
    '''
    authentication_classes=[JWTauthentication]
    permissions=[IsAuthenticated]

    def post(self,request):
        try:
            user=get_user_from_tenant(request)
            tenant=get_tenant(request)
            check_availability=user_available(tenant)
            if not check_availability:
                return Response(data={'message':'Kindly upgrade the plan for more users'},status=status.HTTP_400_BAD_REQUEST)
            if user.is_admin:
                sz=WorkSerializer(data=request.data)
                if sz.is_valid():
                    users,passwords=sz.create(sz.validated_data,tenant)
                    emails=[user.email for user in users]
                    send_bulk_email.delay(emails,passwords)
                    return Response(data={"message":'Accounts created'},status=status.HTTP_200_OK)
                return Response(data={"message":sz.errors},status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({"message":"You don't have privelages to perform this action"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            
            return Response({"message":str(e)},status=status.HTTP_400_BAD_REQUEST)


class Get_User_Logs(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def get(self,request,username):
        try:
            tenant=get_tenant(request)
            obj=NewUser.objects.filter(tenant=tenant).filter(username=username).first()
            if obj:
                user=get_user_from_tenant(request)
                if user==obj or user.is_admin:
                    logs=obj.user_logs.all()
                    if len(logs)==0:
                        return Response({"message":"no logs"},status.HTTP_200_OK)
                    sz=Logs_Serializer(logs,many=True)
        
                    return Response(data=sz.data,status=status.HTTP_200_OK)
                else:
                    return Response(data={"message":"You don't have privelages to access this resource"},status=status.HTTP_400_BAD_REQUEST)
            else:
                
                return Response(data={"message":f"{username} does not exist"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)

class Get_All_Logs(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def get(self,request):
        try:
            user=get_user_from_tenant(request)
            tenant=get_tenant(request)
            if user.is_admin:
                all_user=NewUser.objects.filter(tenant=tenant).all()
                logs=User_logs.objects.filter(user__in=all_user)
                sz=Logs_Serializer(logs,many=True)

                return Response(sz.data,status=status.HTTP_200_OK)
            else:
                return Response(data={"message":"You don't have privelages to access this utlity"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)

class AdminCreateUser(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def post(self,request):
        try:

            tenant=get_tenant(request)
            check_availability=user_available(tenant)
            if not check_availability:
                return Response(data={'message':'Kindly upgrade the plan for more users'},status=status.HTTP_400_BAD_REQUEST)
            name=request.data['name']
            email=request.data['email']
            username=request.data['username']
            is_admin=False
            is_activated=True
            is_active=True
            password=id_generator_2(size=10)
            user=NewUser(name=name,email=email,username=username,is_admin=is_admin,is_active=is_active,is_activated=is_activated,tenant=tenant)
            user.set_password(password)
            user.save()
            send_bulk_email.delay([user.email],[password])
            return Response(data={"message":"user account created"},status=status.HTTP_200_OK)
        except Exception as e:
            
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)



class Admin_Delete_All_Users(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def post(self,request):
        try:
            tenant=get_tenant(request)
            if 'user_emails' not in request.data:
                return Response(data={"message":f'user email not in data'},status=status.HTTP_400_BAD_REQUEST)
            users=[]
            for i in request.data['user_emails']:
                user=NewUser.objects.filter(tenant=tenant).filter(email=i).first()
                if not user:
                    return Response(data={"message":f'{i} does not exist'},status=status.HTTP_400_BAD_REQUEST)
                users.append(user)
            NewUser.objects.filter(tenant=tenant).filter(email_in=request.data['user_emails']).delete()
            return Response(data={"message":f'Deleted Successfully'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message":{e}},status=status.HTTP_400_BAD_REQUEST)




class Notification_System(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def get(self, request):
        try:
            request_received_time = timezone.now()
            ten_seconds_later = request_received_time + datetime.timedelta(seconds=30)
            user = get_user_from_tenant(request)
            while timezone.now() < ten_seconds_later:
                changed_items = []
                for i in Notifications.objects.filter(user=user, read=False):
                    changed_items.append(i)
                    i.read = True
                    i.save()
                if changed_items:
                    tmpJson = Notification_Serializer(changed_items, many=True)
                    return Response(data=tmpJson.data, status=status.HTTP_200_OK)
                gevent.sleep(0.1) # sleep for 100ms before checking again
            return Response([])
        except Exception as e:
            return Response(data={"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class Verify_Token(APIView):


    def get(self,request,token):
        try:
            user=get_user(request,token)
            tenant=get_tenant(request)
            user=NewUser.objects.filter(tenant=tenant).filter(username=user).first()
            if not user:
                return Response(status=403)
            bt=BlacklistedToken.objects.filter(token=token).first()
            print(bt)
            if bt:
                return Response(status=403)
            return Response(status=status.HTTP_200_OK)
        except NewUser.DoesNotExist:
            return Response(status=403)
        except Exception as e:
            return Response(status=403)



class Notification_System_Old(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]


    def get(self, request):

        try:
            user=get_user_from_tenant(request)
            all_notif=user.user_notifications.all()
            if all_notif:
                notif=Notification_Serializer(all_notif,many=True)
                return Response(sorted(notif.data,key=lambda x: x['date'],reverse=True),status=status.HTTP_200_OK)
            else:
                return Response(data={"message":"No notifications"},status=status.HTTP_200_OK)
                
    
        except Exception as e:
            
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)



class Leave_Group(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def delete(self,request,urlhash):
        try:
            user=get_user_from_tenant(request)
            grp=People_Groups.objects.filter(group_hash=urlhash).first()
            grp_per=Group_Permissions.objects.filter(group=grp,user=user).first()
            grp_per.delete()
            return Response(data={'message':"successfully left group"},status=status.HTTP_200_OK)


        except Exception as e:
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)


class Clear_Notifications(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def delete(self,request):
        try:
            user=get_user_from_tenant(request)
            obj=Notifications.objects.filter(user=user).all()
            obj.delete()
            return Response(data={'message':f'successfully cleared'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(message=f'{e}',status=status.HTTP_400_BAD_REQUEST)

class Add_Favourite(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def put(self,request,link_hash):
        try:
            user=get_user_from_tenant(request)
            grp=People_Groups.objects.get(group_hash=link_hash)
            per=Group_Permissions.objects.get(group=grp,user=user)
            per.is_favourite=not per.is_favourite
            per.save()
            return Response(data={'message':f'successfully updated'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(message=f'{e}',status=status.HTTP_400_BAD_REQUEST)





class CheckFileInfo(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    def get(self,request,file_id):
        try:
                user=get_user(request)
                user=NewUser.objects.get(username=user)
                file=Files_Model.objects.get(urlhash=file_id)
                if file.owner==user:
                    res = {
                        'BaseFileName': file.file_name,
                        'Size': file.content.size,
                        'UserId': user.username,
                        'UserCanWrite': True,
                        'HidePrintOption':False,
                        'DisableExport':False,
                        'DisablePrint':False,
                    }
                else:
                    share=Internal_Share.objects.filter(owner=file.owner,shared_with=user,file_hash=file).first()
                    if not share:
                        share=Internal_Share_Folders.search_parent_file(user,file)    
                    res = {
                        'BaseFileName': file.file_name,
                        'Size': file.content.size,
                        'UserId': user.username,
                        'UserCanWrite': share.can_add_delete_content,
                        'HidePrintOption':share.can_download_content,
                        'DisableExport':share.can_download_content,
                        'DisablePrint':share.can_download_content,
            
                    }
            

                return Response(data=res,status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data=f'{e}',status=status.HTTP_400_BAD_REQUEST)



class CheckFileInfo_Link(APIView):
    authentication_classes = []
    permissions = []
    def get(self,request,file_id):
        #link_hash _ file_hash
        try:
                link_hash,file_hash=file_id.split('_')
                file=Files_Model.objects.get(urlhash=file_hash)
                link=Link_Model.objects.filter(link_hash=link_hash,file_hash__in=[file]).first()
                if not link:
                    link=Link_Model.search_parent_file(link_hash,file)
                if link:
                        res = {
                            'BaseFileName': file.file_name,
                            'Size': file.content.size,
                            'UserId': 'Guest',
                            'UserCanWrite':False,
                            'HidePrintOption':not link.is_downloadable,
                            'DisableExport':not link.is_downloadable,
                            'DisablePrint':not link.is_downloadable,
                            'WatermarkText':link.owner.username,
                        }
                        print('data sent')
                        return Response(data=res,status=status.HTTP_200_OK)
                return Response(data=f'error not authorized ',status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            
            return Response(data=f'{e}',status=status.HTTP_400_BAD_REQUEST)


class GetFileLink(APIView):
    authentication_classes = []
    permissions = []
    def get(self,request,file_id):
        try:
            link_hash,file_id=file_id.split('_')
            file=Files_Model.objects.get(urlhash=file_id)
            link=Link_Model.objects.filter(link_hash=link_hash,file_hash__in=[file]).first()
            if not link:
                    link=Link_Model.search_parent_file(link_hash,file)
            if link:
                file_mimetype=mimetypes.guess_type(file.file_name)
                if file_mimetype is not None:
                    response = HttpResponse(file.content, content_type=file_mimetype)
                    response['Content-Disposition'] = 'attachment; filename=' + file.file_name
                    return response
                
                return Response(data={'message':'cant render file'},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(message=f'{e}',status=status.HTTP_400_BAD_REQUEST)





    


class GetFile(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    def get(self,request,file_id):
        try:
            user=get_user(request)
            user=NewUser.objects.get(username=user)
            file=Files_Model.objects.get(urlhash=file_id)
            if file.owner==user:
                file_mimetype=mimetypes.guess_type(file.file_name)
                if file_mimetype is not None:
                    response = HttpResponse(file.content, content_type=file_mimetype)
                    response['Content-Disposition'] = 'attachment; filename=' + file.file_name
                    return response
            share=Internal_Share.objects.filter(owner=file.owner,shared_with=user,file_hash=file).first()
            if not share:
                    share=Internal_Share_Folders.search_parent_file(user=user,file=file)
            if share:
                file_mimetype=mimetypes.guess_type(file.file_name)
                if file_mimetype is not None:
                    response = HttpResponse(file.content, content_type=file_mimetype)
                    response['Content-Disposition'] = 'attachment; filename=' + file.file_name
                    return response
                return Response(data={'message':'file cannot be rendered'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={'message':f'{e}'},status=status.HTTP_400_BAD_REQUEST)

    def post(self,request,file_id):
        try:
            user=get_user(request)
            user=NewUser.objects.get(username=user)
            file=Files_Model.objects.get(urlhash=file_id)
            if file.owner==user:
                content = request.read()
                file_content=ContentFile(content,file.file_name)

                file.content=file_content
                file.resave()
                return Response(data={'message':'successfully saved file'},status=status.HTTP_200_OK)
            share=Internal_Share.objects.filter(owner=file.owner,shared_with=user,file_hash=file).first()
            if not share:
                    share=Internal_Share_Folders.search_parent_file(user=user,file=file)
            if share.can_add_delete_content:
                content = request.read()
                file_content=ContentFile(content,file.file_name)

                file.content=file_content
                file.resave()
                return Response(data={'message':'successfully saved file'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(message=f'{e}',status=status.HTTP_400_BAD_REQUEST)


    


class CheckFileInfoGroup(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def get(self,request,group_hash_fileid):
        try:
            group_hash,file_id=group_hash_fileid.split('_')
            user=get_user(request)
            user=NewUser.objects.get(username=user)
            file=Files_Model.objects.get(urlhash=file_id)
            path=file.path().split('/')[:-1]
            group=People_Groups.objects.filter(group_hash=group_hash,files__in=[file]).first()
            if not group:
                group=People_Groups.search_parent_file(group_hash,file)
            perm=Group_Permissions.objects.get(group=group,user=user)
            if perm:
                res = {
                        'BaseFileName': file.file_name,
                        'Size': file.content.size,
                        'UserId': user.username,
                        'UserCanWrite': perm.can_add_delete_content,
                        'HidePrintOption':perm.can_download_content,
                        'DisableExport':perm.can_download_content,
                        'DisablePrint':perm.can_download_content,
            
                    }
            return Response(data=res,status=status.HTTP_200_OK)

        except Exception as e:
            
            return Response(data=f'{e}',status=status.HTTP_400_BAD_REQUEST)


class GetFileGroup(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    def get(self,request,file_id):
        try:
            user=get_user(request)
            user=NewUser.objects.get(username=user)
            group_hash,file_id=file_id.split('_')
            file=Files_Model.objects.get(urlhash=file_id)
            group=People_Groups.objects.filter(group_hash=group_hash,files__in=[file]).first()
            path=file.path().split('/')[:-1]
            group=People_Groups.objects.filter(group_hash=group_hash,files__in=[file]).first()
            if not group:
                group=People_Groups.search_parent_file(group_hash,file)
            perm=Group_Permissions.objects.get(group=group,user=user)
            if perm:
                file_mimetype=mimetypes.guess_type(file.file_name)
                if file_mimetype is not None:
                    response = HttpResponse(file.content, content_type=file_mimetype)
                    response['Content-Disposition'] = 'attachment; filename=' + file.file_name
                    return response
                
                return Response(data={'message':'cant render file'},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(message=f'{e}',status=status.HTTP_400_BAD_REQUEST)

    def post(self,request,file_id):
        try:
            group_hash,file_id=file_id.split('_')
            user=get_user(request)
            user=NewUser.objects.get(username=user)
            file=Files_Model.objects.get(urlhash=file_id)
            group=People_Groups.objects.filter(group_hash=group_hash,files__in=[file]).first()
            if not group:
                group=People_Groups.search_parent_file(group_hash,file)
            perm=Group_Permissions.objects.get(group=group,user=user)
            if perm and perm.can_add_delete_content:
                content = request.read()
                file_content=ContentFile(content,file.file_name)

                file.content=file_content
                file.resave()
                return Response(data={'message':'successfully saved file'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(message=f'{e}',status=status.HTTP_400_BAD_REQUEST)





class Forgot_Subdomain(APIView):
    def post(self,request,*args, **kwargs):
        try:
            email=request.data['email']
            user=NewUser.objects.get(email=email)
            tenant=user.tenant
            message=f'subdomain={tenant.subdomain} email : {user.email}'
            #send_email('Forgot Subdomain',message,'info@varency.com',[email])
            return Response(data={'message':'sent details on email'},status=status.HTTP_200_OK)
        except Exception as e:

            return Response(data=f'{e}',status=status.HTTP_400_BAD_REQUEST)


class Query_Subuser_Email(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    def get(self,request,query):
        try:
            tenant=get_tenant(request)
            all_users=NewUser.objects.filter(tenant=tenant).filter(email__contains=query)
            sz=UserSerializer(all_users,many=True)
        
            return Response(data=sz.data,status=status.HTTP_200_OK)
        except Exception as e:

            return Response(data=f'{e}',status=status.HTTP_400_BAD_REQUEST)


