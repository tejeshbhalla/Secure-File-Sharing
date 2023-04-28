from content.extra_utils import check_parent
from files.sub_utils import get_tenant, get_user_from_tenant
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from files.jwt_utils import JWTauthentication 
from .serializers import DetailFileSerializer,FolderSerializer,DetailFolderSerializer,FileSerializer,Link_Serializer, Request_File_Serializer,Detail_Link_Serializer
from files.models import NewUser,People_Groups,Group_Permissions
from .models import Folder,Files_Model, Internal_Share_Folders,Link_Model,Internal_Share,Link_logs, Request_File
from .utils import get_video_status,get_video_otp,create_media_jwt,RangeFileWrapper,download_url_generate_sas,create_notifications, get_client_ip, get_user,send_mail_helper,delete_keys,upload_path_folder
from Varency.settings import FRONT_END_URL,TIME_ZONE,BACKEND_URL
import datetime 
from django.utils import timezone
import pytz 
from annoying.functions import get_object_or_None
from django.core.files.base import  File
from django.http import FileResponse
import json
from files.serializers import UserSerializer,DetailGroupSerializer
from rest_framework.decorators import api_view, throttle_classes
from rest_framework.throttling import UserRateThrottle
import mimetypes
from azure.storage.blob import BlobServiceClient
from Varency.settings import AZURE_ACCOUNT_NAME,AZURE_CONTAINER,AZURE_CONNECTION_STRING,SECRET_KEY
import jwt
from zipfile import ZipFile
from azure.storage.blob import BlobServiceClient,ContentSettings
from django.http import StreamingHttpResponse
from stream_zip import ZIP_32, stream_zip
import uuid
from azure.core.exceptions import ResourceNotFoundError
from .tasks import upload_video_to_vdocipher
from django.core.cache import cache
from django.db.models import Q
import gevent
from .utils import validate_share





class CreateFolderView(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def post(self,request, *args, **kwargs):
        try:

            user=get_user_from_tenant(request)
            tenant=get_tenant(request)
            serializer=FolderSerializer(data=request.data)
            if serializer.is_valid():
                serializer.validated_data['owner']=user
                obj=serializer.create(serializer.validated_data,tenant)
                if obj!=None:
                    return Response(data={'message':'folder created','folder_id':f"{obj.urlhash}"},status=status.HTTP_200_OK)
                else:
                    return Response(data={'message':"fatal error wrong input"})
            return Response(data={'message':f'{serializer.errors}'},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            
            return Response(data={'message':f"error {e}"},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request, urlhash):
        if len(urlhash)!=6:
            return Response(data={'message':f'invalid request'},status=status.HTTP_400_BAD_REQUEST)
        try:
            tenant=get_tenant(request)
            serializer=FolderSerializer(data=request.data,partial=True)
            if serializer.is_valid():
                m=serializer.update(urlhash=urlhash,validated_data=serializer.validated_data,tenant=tenant)
                if m==None:
                    return Response(data={'message':f'failed updating folder'})
                return Response(data={'message':f' updated folder'})
            return Response(data={'message':f'{serializer.errors}'})
        except Exception as e:
            return Response(data={'message':f'{e}'},status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, urlhash):
        try :
            if len(urlhash)!=6:
                return Response(data={'message':f'invalid request'},status=status.HTTP_400_BAD_REQUEST)
            folder=Folder.objects.get(urlhash=urlhash)
            if not folder:
                return Response(data={'message':f'folder not found'})
            user=get_user_from_tenant(request)

            if folder.owner != user:
                return Response(data={'message':"You can't delete this folder"},status=status.HTTP_400_BAD_REQUEST)
            folder.delete()
            return Response(data={'message':'success'})
        except Exception as e:
            
            return Response(data={'message':f'error deleting folder'},status=status.HTTP_400_BAD_REQUEST)


class FolderDetailView(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def get(self, request,urlhash):
        try:
        
            owner=get_user_from_tenant(request)
            if urlhash=='root':
                
                folders=Folder.objects.all().filter(parent=None).filter(owner=owner)
                files=Files_Model.objects.all().filter(folder=None).filter(owner=owner)
                data={"name":"root","parent":None,"owner":{"email":owner.email,"username":owner.username,"total_space_utilised":owner.storage_amount_used,
            "total_available_space":owner.total_available_space()},"files":[],"children":[]}
                for i in folders:
                    if i.deleted:
                        continue
                    all_internal_folders=Internal_Share_Folders.objects.filter(owner=owner,folder_hash=i).all()
                    users=[{'username':user.shared_with.username,'email':user.shared_with.email,'can_add_delete_content':user.can_add_delete_content,'can_share_content':user.can_share_content,
                    'can_download_content':user.can_download_content} for user in all_internal_folders]
                    data['children'].append({"urlhash":i.urlhash,"name":i.name,"owner":i.owner.username,"date_created":str(i.date_created)[0:11],"date_modified":i.date_modified,"is_folder":True,'shared_with':users,
                    'download_link':f'{BACKEND_URL}api/content/folder_download/{create_media_jwt(i,get_client_ip(request))}'})
                for i in files:
                    if i.deleted:
                        continue
                    all_internal_files=Internal_Share.objects.filter(owner=owner,file_hash=i).all()
                    
                    users=[{'username':user.shared_with.username,'email':user.shared_with.email,'can_add_delete_content':user.can_add_delete_content,'can_share_content':user.can_share_content,
                    'can_download_content':user.can_download_content,'is_proctored':user.is_proctored} for user in all_internal_files]
                    data['files'].append({"urlhash":i.urlhash,"name":i.file_name,"url":f'{BACKEND_URL}api/content/media/{create_media_jwt(i,get_client_ip(request))}',"size":str(int(i.content.size/1024))+" kb","owner":i.owner.username,"date_created":str(i.date_uploaded)[0:11],'is_file':True,'shared_with':users,
                                          'download_link':download_url_generate_sas(i,get_client_ip(request))})

                return Response(data=data,status=status.HTTP_200_OK)
            folder=Folder.objects.get(urlhash=urlhash)
            if folder.deleted:
                return Response(data={"message":"folder is deleted recover to view"},status=status.HTTP_400_BAD_REQUEST)

            serializer=DetailFolderSerializer(folder)
            data=serializer.data
            data['children']=[]
            data['files']=[]
            data["owner"]={"email":owner.email,"username":owner.username,"total_space_utilised":owner.storage_amount_used,
            "total_available_space":owner.total_available_space()}
            for i in folder.children.all():
                if i.deleted:
                    continue
                all_internal_folders=i.internal_link_folders.all()
                users=[user.shared_with.username for user in all_internal_folders]
                data['children'].append({"urlhash":i.urlhash,"name":i.name,"owner":i.owner.username,"date_created":i.date_created,"date_modified":i.date_modified,'shared_with':users,
                                         'download_link':f'{BACKEND_URL}api/content/folder_download/{create_media_jwt(i,get_client_ip(request))}'})
            for i in folder.files.all():
                if i.deleted:
                    continue
                all_internal_files=i.internal_link_files.all()
                users=[user.shared_with.username for user in all_internal_files]
                data['files'].append({"urlhash":i.urlhash,"name":i.file_name,"url":f'{BACKEND_URL}api/content/media/{create_media_jwt(i,get_client_ip(request))}',"size":str(int(i.content.size/1024))+" kb","owner":i.owner.username,"date_created":str(i.date_uploaded)[0:11],'is_file':True,'shared_with':users
                                      ,'download_link':download_url_generate_sas(i,get_client_ip(request))})
            if folder.owner!=owner:
                data['path']=['root',data['path'][-1]]
                data['hash_path']=['root',data['hash_path'][-1]]
            return Response(data=data,status=status.HTTP_200_OK)
        except Exception as e:
            
            return Response(data={"message":"error"},status=status.HTTP_400_BAD_REQUEST)

class Internal_Folder_Detail(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def get(self,request,urlhash):
        try:
            user=get_user_from_tenant(request)

            if urlhash=='root':
                all_internals_files=user.files_shared_with_you.all()
                all_internals_folders=user.folders_shared_with_you.all()
                data={"name":"root","parent":None,"files":[],"children":[],'requests':[]}
                for i in all_internals_folders:
    
                    folders=i.folder_hash
                    if folders.deleted:
                        continue
                    data['children'].append({"urlhash":folders.urlhash,"name":folders.name,"owner":folders.owner.username,
                    "date_created":folders.date_created,"date_modified":folders.date_modified,
                    'path':folders.order_parent(),
                    'hash_path':folders.order_parent_urlhash(),'is_downloadable':i.is_downloadable,
                    'can_share_content':i.can_share_content,
                    'can_download_content':i.can_download_content,'is_proctored':i.is_proctored,
                    'can_add_delete_content':i.can_add_delete_content,'download_link':f'{BACKEND_URL}api/content/folder_download/{create_media_jwt(folders,get_client_ip(request))}' if i.can_download_content else None })
                for f in all_internals_files:
                    file=f.file_hash
                    if file.deleted:
                        continue
                    data['files'].append({"urlhash":file.urlhash,"name":file.file_name,
                    "size":str(int(file.content.size/1024))+" kb","owner":file.owner.username,
                    "date_created":str(file.date_uploaded)[0:11],'is_file':True,'is_downloadable':f.is_downloadable,
                    'can_share_content':f.can_share_content,'can_add_delete_content':f.can_add_delete_content,
                    'can_download_content':f.can_download_content,'is_proctored':f.is_proctored,'download_link':download_url_generate_sas(file,get_client_ip(request)) if f.is_downloadable else None})
                all_requests=user.requests_recieved.all()
                for i in all_requests:
                    data['requests'].append({'file_name':i.file_name,'user_to':i.user_to.email,'request_hash':i.request_hash,'user_from':i.user_from.email})
                return Response(data,status.HTTP_200_OK)
            folder=Folder.objects.get(urlhash=urlhash)
            all_internals_folders=user.folders_shared_with_you
            parents=folder.order_parent_urlhash()
            found_parent=False
            j=len(parents)-1
            while j!=0:
                parent=parents[j]
                internal_share_folder=get_object_or_None(Internal_Share_Folders,shared_with=user,folder_hash=Folder.objects.get(urlhash=parent))
                if internal_share_folder:
                    found_parent=True
                    break
                j-=1
            if not found_parent:
                return Response(data={"message":'unauthorized'},status=status.HTTP_400_BAD_REQUEST)
            data={"name":folder.name,"parent":parent,"files":[],"children":[],'parent_permissions':{'is_downloadable':internal_share_folder.is_downloadable,
                    'can_share_content':internal_share_folder.can_share_content,
                    'can_download_content':internal_share_folder.can_download_content,'is_proctored':internal_share_folder.is_proctored,'can_add_delete':internal_share_folder.can_add_delete_content}}
            files=folder.files.all()
            folders=folder.children.all()
            for i in files:
                 if i.deleted:
                     continue
                 data['files'].append({"urlhash":i.urlhash,"name":i.file_name,
                    "size":str(int(i.content.size/1024))+" kb","owner":i.owner.username,
                    "date_created":str(i.date_uploaded)[0:11],'is_file':True,'is_downloadable':internal_share_folder.is_downloadable,
                    'can_share_content':internal_share_folder.can_share_content,
                    'can_add_delete_content':internal_share_folder.can_add_delete_content,
                    'can_download_content':internal_share_folder.can_download_content,'is_proctored':internal_share_folder.is_proctored,
                    'download_link':download_url_generate_sas(i,get_client_ip(request)) if internal_share_folder.can_download_content else None})
            for j in folders:
                if j.deleted:
                    continue
                data['children'].append({"urlhash":j.urlhash,"name":j.name,"owner":j.owner.username,"date_created":j.date_created,"date_modified":j.date_modified,'path':j.order_parent(),'hash_path':j.order_parent_urlhash(),
                'is_downloadable':internal_share_folder.is_downloadable,
                    'can_share_content':internal_share_folder.can_share_content,
                    'can_download_content':internal_share_folder.can_download_content,'is_proctored':internal_share_folder.is_proctored,
                    'can_add_delete_content':internal_share_folder.can_add_delete_content,
                    'download_link':f'{BACKEND_URL}api/content/folder_download/{create_media_jwt(j,get_client_ip(request))}' if internal_share_folder.can_download_content else None})
            return Response(data,status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={"message":f"{e}"},status=status.HTTP_400_BAD_REQUEST)


       

#files view 
class CreateFilesView(APIView):
    authentication_classes =[JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    
    def post(self, request,urlhash):
        
        try:
            serializer=FileSerializer(data=request.data)
            if serializer.is_valid():
                if urlhash=='root':
                    folder=None
                else:
                    folder=Folder.objects.get(urlhash=urlhash)
                
                user=get_user_from_tenant(request)
                serializer.validated_data['owner']=user
                if folder and folder.owner!=user:
                    per=Internal_Share_Folders.objects.filter(folder_hash=folder,shared_with=user).first()
                    parent=Internal_Share_Folders.search_parent(user,folder)
                    if parent and parent.can_add_delete_content:
                        serializer.validated_data['owner']=folder.owner
                    elif per and per.can_add_delete_content:
                        serializer.validated_data['owner']=per.owner
                    else:
                        return Response({'message':"Don't have privelage to share"},status=status.HTTP_400_BAD_REQUEST)
                serializer.validated_data['folder']=folder
                obj=serializer.save()
                return Response(data={"name":obj.file_name,'urlhash':obj.urlhash,'message':"file created"},status=status.HTTP_200_OK)
            else:
                return Response(data={"message":f"{serializer.errors}"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            
            return Response(data={"message":f"{e}"},status=status.HTTP_400_BAD_REQUEST)


    def delete(self,request, urlhash):
        try:
            files=Files_Model.objects.get(urlhash=urlhash)
            if not files:
                return Response(data={"message":f"file does not exist"},status=status.HTTP_400_BAD_REQUEST)
            user=get_user_from_tenant(request)
            if files.owner==user:
                files.delete()
                return Response(data={"message":f"files deleted"},status=status.HTTP_200_OK)
            else:
                per=Internal_Share.objects.filter(file_hash=files,shared_with=user).first()
                parent=Internal_Share_Folders.search_parent_file(user,files)
                if per and per.can_add_delete_content:
                    files.delete()
                    return Response(data={"message":f"files deleted"},status=status.HTTP_200_OK)
                elif parent and parent.can_add_delete_content:
                    files.delete()
                    return Response(data={"message":f"files deleted"},status=status.HTTP_200_OK)
            return Response(data={"message":f"You can't delete this file"},status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            
            return Response(data={"message":f"{e}"},status=status.HTTP_400_BAD_REQUEST)

    def put(self,request,urlhash):
        try:
            if 'file_name' not in request.data:
                return Response(data={'message':'File Name not in data'},status=status.HTTP_400_BAD_REQUEST)
            user=get_user_from_tenant(request)
            file=Files_Model.objects.get(urlhash=urlhash)
            per=Internal_Share.objects.filter(file_hash=file,shared_with=user).first()
            parent=Internal_Share_Folders.search_parent_file(user,file)
            if per and per.can_add_delete_content:
                file.file_name=request.data['file_name']
                file.save()
                return Response(data={"message":f"file updated"},status=status.HTTP_200_OK)
            elif parent and parent.can_add_delete_content:
                file.file_name=request.data['file_name']
                file.save()
                return Response(data={"message":f"file updated"},status=status.HTTP_200_OK)

            if len(request.data['file_name']):
                file.file_name=request.data['file_name']
                file.save()
                return Response(data={"message":"file updated"},status=status.HTTP_200_OK)
            else:
                return Response(data={'message':'Error occured'},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(data={"message":{e}},status=status.HTTP_400_BAD_REQUEST)

            
class View_File(APIView):
     authentication_classes =[JWTauthentication]
     permissions = [IsAuthenticated]
     throttle_classes = [UserRateThrottle]
     def get(self,request,url_file):
        try:
            user=get_user_from_tenant(request)
            files=Files_Model.objects.filter(urlhash=url_file)[0]
            if files.owner==user or user in files.shared_with.all():
                   return Response(data={"name":files.file_name,"urlhash":files.urlhash,"owner":files.owner.username,'content':files.content.url,'type':str(files.content.file).split("/")[-1].split('.')[-1]}, status=status.HTTP_200_OK)
            return Response(data={"message":"Not authorized"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(data={"message":f"{e}"},status=status.HTTP_400_BAD_REQUEST)

class Share_File(APIView):
    authentication_classes =[JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    
    def post(self, request, *args, **kwargs):
        try:
            user=get_user(request)
            tenant=get_tenant(request)
            owner=get_user_from_tenant(request)

            if 'shared_with' not in request.data:
                return Response(data={"message":f'shared with not in data'},status=status.HTTP_400_BAD_REQUEST)
            if "file_hash" not in request.data:
                return Response(data={"message":f'shared files not in data'},status=status.HTTP_400_BAD_REQUEST)     
            if 'folder_hash' not in   request.data:
                return Response(data={"message":f"shared folders not in data"},status=status.HTTP_400_BAD_REQUEST)
            for users in request.data['shared_with']:
                    user=get_object_or_None(NewUser,email=users,tenant=tenant)
                    if user==owner:
                        return Response(data={'message':"Can't share with yourself"})
                    can_add_delete_content=request.data['can_add_delete_content']
                    can_share_content=request.data['can_share_content']
                    can_download_content=request.data['can_download_content']
                    is_proctored=request.data['is_proctored']

                    if user==None:
                        return Response(data={"message":f"{users} does not exist"},status=status.HTTP_400_BAD_REQUEST)
                    
                    for file_hash in request.data['file_hash']:
                        obj=get_object_or_None(Files_Model,urlhash=file_hash)
                        file=Files_Model.objects.get(urlhash=file_hash)
                        if obj==None or obj.owner!=owner:
                            parent_share=Internal_Share_Folders.search_parent_file(owner,file)
                            if parent_share:
                                validate_share(parent_share,request.data)
                                obj=Internal_Share(owner=file.owner,shared_with=user,file_hash=file)
                                obj.can_add_delete_content=can_add_delete_content
                                obj.can_share_content=can_share_content
                                obj.can_download_content=can_download_content
                                obj.is_proctored=is_proctored
                                obj.save()
                                return Response(data={'message':f'Successfully shared files'},status=status.HTTP_400_BAD_REQUEST)
                            return Response(data={"message":f"You don't have privelages to share {file_hash} or file does not exist"},status=status.HTTP_400_BAD_REQUEST)
                        else:
                            obj=get_object_or_None(Internal_Share,shared_with=user,owner=owner,file_hash=file)
                            if obj:
                                obj.can_add_delete_content=can_add_delete_content
                                obj.can_share_content=can_share_content
                                obj.can_download_content=can_download_content
                                obj.is_proctored=is_proctored
                                obj.save()
                            else:
                                obj=Internal_Share(owner=owner,shared_with=user,file_hash=file)
                                obj.can_add_delete_content=can_add_delete_content
                                obj.can_share_content=can_share_content
                                obj.can_download_content=can_download_content
                                obj.is_proctored=is_proctored
                                obj.save()
                    for folder_hash in request.data['folder_hash']:
                        folder=get_object_or_None(Folder,urlhash=folder_hash)
                        if folder==None or folder.owner!=owner:
                            parent_share=Internal_Share_Folders.search_parent(owner,folder)
                            if parent_share:
                                validate_share(parent_share,request.data)
                                obj=Internal_Share_Folders(owner=folder.owner,shared_with=user,folder_hash=folder)
                                obj.can_add_delete_content=can_add_delete_content
                                obj.can_share_content=can_share_content
                                obj.can_download_content=can_download_content
                                obj.is_proctored=is_proctored
                                obj.save()
                                return Response(data={'message':f'Successfully shared folder'},status=status.HTTP_400_BAD_REQUEST)
                            return Response(data={"message":f"You don't have privelages to share {folder_hash} or file does not exist"},status=status.HTTP_400_BAD_REQUEST)
                        
                        obj=get_object_or_None(Internal_Share_Folders,shared_with=user,owner=owner,folder_hash=folder)
                        if obj:
                            obj.can_add_delete_content=can_add_delete_content
                            obj.can_share_content=can_share_content
                            obj.can_download_content=can_download_content
                            obj.is_proctored=is_proctored
                            obj.save()
                        else:
                            obj=Internal_Share_Folders(owner=owner,shared_with=user,folder_hash=folder)
                            obj.can_add_delete_content=can_add_delete_content
                            obj.can_share_content=can_share_content
                            obj.can_download_content=can_download_content
                            obj.is_proctored=is_proctored
                            obj.save()

                        create_notifications(user,extras=f'{owner.username} shared files with you')
            return Response(data={"message":f"Successfully shared "},status=status.HTTP_200_OK)
            
        except Exception as e:
            
            return Response(data={"message":f"{e}"},status=status.HTTP_400_BAD_REQUEST)

    def delete(self,request,urlhash):
        try:
            tenant=get_tenant(request)
            file=get_object_or_None(Files_Model,urlhash=urlhash)
            folder=get_object_or_None(Folder,urlhash=urlhash)
            if not file and not folder:
                return Response(data={"message":f"Not found {urlhash}"},status=status.HTTP_400_BAD_REQUEST)
            user=get_user(request)
            owner=get_user_from_tenant(request)
            if 'email' not in request.data:
                return Response(data={"message":'email not in data'},status=status.HTTP_400_BAD_REQUEST)
            user=NewUser.objects.get(email=request.data['email'],tenant=tenant)
            if file:
                file_share=Internal_Share.objects.get(shared_with=user,owner=owner,file_hash=file)
                file_share.delete()
            if folder:
                folder_share=Internal_Share_Folders.objects.get(shared_with=user,owner=owner,folder_hash=folder)
                folder_share.delete()
            return Response(data={"message":'successfully removed'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message":f'{str(e)}'},status=status.HTTP_400_BAD_REQUEST)
    def put(self,request,urlhash):
        try:
            tenant=get_tenant(request)
            file=get_object_or_None(Files_Model,urlhash=urlhash)
            folder=get_object_or_None(Folder,urlhash=urlhash)
            if not file and not folder:
                return Response(data={"message":f"Not found {urlhash}"},status=status.HTTP_400_BAD_REQUEST)
            user=get_user(request)
            owner=get_user_from_tenant(request)
            
            if 'email' not in request.data:
                return Response(data={"message":'email not in data'},status=status.HTTP_400_BAD_REQUEST)
            if 'permissions' not in request.data:
                return Response(data={'message':'permission not in data'},status=status.HTTP_400_BAD_REQUEST)
            user=NewUser.objects.filter(tenant=tenant).filter(email=request.data['email']).first()
            if file:
                file_share=Internal_Share.objects.get(shared_with=user,owner=owner,file_hash=file)
                file_share.can_add_delete_content=request.data['permissions']['can_add_delete_content']
                file_share.can_share_content=request.data['permissions']['can_share_content']
                file_share.can_download_content=request.data['permissions']['can_download_content']
                file_share.is_proctored=request.data['permissions']['is_proctored']
                file_share.save()
            if folder:
                folder_share=Internal_Share_Folders.objects.get(shared_with=user,owner=owner,folder_hash=folder)
                folder_share.can_add_delete_content=request.data['permissions']['can_add_delete_content']
                folder_share.can_share_content=request.data['permissions']['can_share_content']
                folder_share.can_download_content=request.data['permissions']['can_download_content']
                folder_share.save()
            return Response(data={"message":'successfully removed'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message":f'{e}'},status=status.HTTP_400_BAD_REQUEST)


class Share_File_Link(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def post(self, request):
        try:
            tenant=get_tenant(request)
            if request.data['shared_with'][0]=='':
                request.data['shared_with'] = []
            sz=Link_Serializer(data=request.data)
            if sz.is_valid():
                
                user=get_user_from_tenant(request)
                
                if sz.validated_data['access_type']=='client':
                    obj=sz.create(sz.validated_data,user,'client',tenant) 
                    
                    if obj.password:
                        custom=request.data['custom_password']

                        if len(custom)>0:
                            obj.password=custom
                            obj.save()
                        link=f'https://{tenant.subdomain}.{FRONT_END_URL}view/link_detail/{obj.link_hash}/none'
                    else:
                        link=f'https://{tenant.subdomain}.{FRONT_END_URL}view/link_detail/{obj.link_hash}/none'
                    
                    log=Link_logs()
                    log.link=obj
                    log.actions=json.dumps({"owner":obj.owner.email,"link":link,"generated_on":str(obj.generated_on),"deleted_on":"None","clicks":[]})
                    log.owner=obj.owner
                    log.save()
                    obj.link_type='mail'
                    user=obj.owner
                    if not obj.prevent_forwarding:
                        obj.is_approved=True
                    obj.save()
                    user.save()

                    
                    send_mail_helper(request.data['shared_with'],link,obj.link_hash,obj.password,obj.owner.username,obj.prevent_forwarding)
                    return Response(data={'message':"email sent to user"},status=status.HTTP_200_OK)
                obj=sz.create(sz.validated_data,user,'employee',tenant)
                #link=f'{get_current_site(request)}/api/content/link_file/visit/{obj.link_hash}'
                if obj.password:
                    custom=request.data['custom_password']

                    if len(custom)>0:
                        obj.password=custom
                        obj.save()
                    link=f'https://{tenant.subdomain}.{FRONT_END_URL}view/link_detail/{obj.link_hash}/none'

                else:
                    link=f'https://{tenant.subdomain}.{FRONT_END_URL}view/link_detail/{obj.link_hash}/none'
                log=Link_logs()
                log.link=obj
                log.actions=json.dumps({"owner":obj.owner.email,"link":link,"generated_on":str(obj.generated_on),"deleted_on":"None","clicks":[]})
                log.owner=obj.owner
                log.save()
                obj.link_type='link'
                user=obj.owner
                obj.is_approved=True
                obj.save()
                user.save()
                return Response(data={"data":{"link":link,'password':obj.password}},status=status.HTTP_200_OK)
            else:
                return Response(data={"message":f"{sz.errors}'"},status=status.HTTP_400_BAD_REQUEST)
    
        except Exception as e:
            
            return Response(data={"message":f"{e}"},status=status.HTTP_400_BAD_REQUEST)



            
class Visit_File_Link(APIView): #check it once 
    #authentication_classes = [JWTauthentication]
    #permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self, request,link_hash):
        try:
            tenant=get_tenant(request)
            obj=Link_Model.objects.filter(link_hash=link_hash).first()
            owner=obj.owner

            if obj.deleted:
                    return Response(data={'message':'Deleted Link'},status=status.HTTP_400_BAD_REQUEST)

            if obj.access_limit==0:
                return Response({"message":"Link visit limit exhausted kindly ask originator to modify"},status=status.HTTP_400_BAD_REQUEST)
            if timezone.now()<obj.expiry_date:

                data={'owner':obj.owner.email,'files':[],'children':[]}
                for i in obj.folder_hash.all():
                    data['children'].append({"urlhash":i.urlhash,"name":i.name})
                for files in obj.file_hash.all():
                    data['files'].append({'name':files.file_name,'urlhash':files.urlhash,'url':files.content.url,'is_proctored':files.is_proctored,'can_download_content':files.is_downloadable})
                if obj.access_limit:
                    obj.access_limit-=1
                    obj.save()
                log=obj.logs
                click={"ip_address":get_client_ip(request),"time":timezone.now()}
                log.actions=json.dumps(json.loads(log.actions)['clicks'].append(click))
                log.save()
                return Response(data=data,status=status.HTTP_200_OK)
            return Response(data={"message":"Link expired"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            
            return Response(data={"message":f"Link expired or removed by originator"},status=status.HTTP_400_BAD_REQUEST)

#fix time here 
class Visit_File_Link_Client(APIView):
    throttle_classes = [UserRateThrottle]

    def post(self, request,link_hash,folder_hash):
        try:
            tenant=get_tenant(request)
            obj=Link_Model.objects.filter(link_hash=link_hash).first()
            if obj.owner.tenant!=tenant:
                return Response(data={'message':'Error invalid request'},status=status.HTTP_400_BAD_REQUEST)
            if folder_hash!='none':
                obj=Link_Model.objects.filter(link_hash=link_hash).first()
                password=request.data['password']
                if obj.is_approved==False:
                    return Response(data={'message':'Link is not approved'},status=status.HTTP_400_BAD_REQUEST)
                if obj.deleted:
                    return Response(data={'message':'Deleted Link'},status=status.HTTP_400_BAD_REQUEST)
                if obj.password and obj.password!=password:
                    log=obj.logs.all().first()
                    click={'message':'Incorrect Password entered',"ip_address":get_client_ip(request),"time":str(timezone.now())}
                    action=json.loads(log.actions)
                    action['clicks'].append(click)
                    log.actions=json.dumps(action)
                    log.save()
                    return Response(data={'message':'Unauthorized access'},status=status.HTTP_400_BAD_REQUEST)

                if not obj.expiry_date or timezone.now()<obj.expiry_date:
                    parents=obj.folder_hash.all()
                    if check_parent(parents,folder_hash):
                        data={'owner':obj.owner.email,'files':[],'children':[]}
                        folder=Folder.objects.filter(urlhash=folder_hash).first()
                        for i in folder.children.all():
                            if i.deleted:
                                continue
                            data["children"].append({'urlhash':i.urlhash,'name':i.name,'download_link':f'{BACKEND_URL}api/content/folder_download/{create_media_jwt(i,get_client_ip(request))}' if obj.is_downloadable else None,'can_download_content':obj.is_downloadable,
                                                     "date_created":str(i.date_created)[0:11],'owner':i.owner.username,'is_folder':True})
                        for i in folder.files.all():
                            if i.deleted:
                                continue
                            data['files'].append({'name':i.file_name,'urlhash':i.urlhash,"url":f'{BACKEND_URL}api/content/media/{create_media_jwt(i,get_client_ip(request))}','can_download_content':obj.is_downloadable,'is_proctored':obj.is_proctored,
                                                  'download_link':download_url_generate_sas(i,get_client_ip(request)) if obj.is_downloadable else None,
                                                  'is_file':True,"date_created":str(i.date_uploaded)[0:11],'owner':i.owner.username})
                        
                        return Response(data=data,status=status.HTTP_200_OK)
                    else:
                        return Response(data={'message':"Unauthorized access"},status=status.HTTP_400_BAD_REQUEST)
            else:
                obj=Link_Model.objects.filter(link_hash=link_hash).first()
                #if obj.access_type!='client':
                    #return Response(data={"message":"Invalid try link is not for client"},status=status.HTTP_400_BAD_REQUEST)
                if obj.access_limit==0:
                    return Response({"message":"link visit limit exhausted kindly ask originator to increase the limit"},status=status.HTTP_400_BAD_REQUEST)
                if not obj.is_approved:
                    return Response(data={'message':'Link is not approved'},status=status.HTTP_400_BAD_REQUEST)
                if obj.deleted:
                    return Response(data={'message':'Deleted Link'},status=status.HTTP_400_BAD_REQUEST)
                if obj.password is not None:
                    if 'password' not in request.data:
                        return Response(data={"message":"Password not sent"},status=status.HTTP_400_BAD_REQUEST)
                    if obj.password!=request.data['password']:
                        log=obj.logs.all().first()
                        click={'message':'Incorrect Password entered',"ip_address":get_client_ip(request),"time":str(timezone.now())}
                        action=json.loads(log.actions)
                        action['clicks'].append(click)
                        log.actions=json.dumps(action)
                        log.save()
                        return Response(data={"message":"invalid password please try again"},status=status.HTTP_400_BAD_REQUEST)
                
                if not obj.expiry_date or timezone.now()<obj.expiry_date:

                    data={'owner':obj.owner.email,'files':[],'children':[]}
                    for i in obj.folder_hash.all():
                        if i.deleted:
                            continue
                        data['children'].append({"urlhash":i.urlhash,"name":i.name,'download_link':f'{BACKEND_URL}api/content/folder_download/{create_media_jwt(i,get_client_ip(request))}' if obj.is_downloadable else None,
                                                 'can_download_content':obj.is_downloadable,
                                                 "date_created":str(i.date_created)[0:11],'owner':i.owner.username,'is_folder':True})
                    for files in obj.file_hash.all():
                        if files.deleted:
                            continue
                        data['files'].append({'name':files.file_name,'urlhash':files.urlhash,"url":f'{BACKEND_URL}content/media/{create_media_jwt(files,get_client_ip(request))}','can_download_content':obj.is_downloadable,'is_proctored':obj.is_proctored,
                                              'download_link':download_url_generate_sas(files,get_client_ip(request)) if obj.is_downloadable else None,
                                              'is_file':True,"date_created":str(files.date_uploaded)[0:11],'owner':files.owner.username})
                    if obj.access_limit:
                        obj.access_limit-=1
                        obj.save()
                    log=obj.logs.all().first()
                    click={"ip_address":get_client_ip(request),"time":str(timezone.now())}
                    action=json.loads(log.actions)
                    action['clicks'].append(click)
                    log.actions=json.dumps(action)
                    log.save()
                    create_notifications(obj,extras={"ip":get_client_ip(request)})
                    return Response(data=data,status=status.HTTP_200_OK)
                return Response(data={"message":"Link expired"},status=status.HTTP_400_BAD_REQUEST)
        except Link_Model.DoesNotExist as e:
            return Response(data={"message":"Link expired or removed"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return Response(data={"message":f"Link expired or removed by originator"},status=status.HTTP_400_BAD_REQUEST)


class Share_Folder(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def post(self, request):
        try:
            if 'urlhash' not in request.data or 'shared_with' not in request.data:
                return Response(data={"message":{"Invalid data no urlhash or shared_with recieved "}})
            user=get_user_from_tenant(request)
            tenant=get_tenant(request)
            for i in request.data['urlhash']:
                folder=Folder.objects.get(urlhash=i)
                if folder.owner != user:
                    return Response(data={"message":{"You dont have privelages to share the files"}})
            users=[NewUser.objects.filter(tenant=tenant).get(email=email).id for email in request.data['shared_with']]
    
            for i in request.data['urlhash']:
                folder=Folder.objects.get(urlhash=i)
                folder.shared_with.set(*[users])
            return Response(data={"message":{"successfully shared folders"}})

        except NewUser.DoesNotExist:
            return Response(data={"message":{"User specified does not exist"}})
        except Folder.DoesNotExist:
            return Response(data={"message":{"folder specified does not exist"}})
        except Exception as e:
            return Response(data={"message":f"{e}"},status=status.HTTP_400_BAD_REQUEST)

                


class Shared_Links_Detail(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self, request, *args, **kwargs):
        try:
            tenant=get_tenant(request)
            user=get_user_from_tenant(request)
            all_links=Link_Model.objects.filter(owner=user).all()
            data=[]
            d={}
            for i in all_links:
                if i.deleted:
                    continue
                d={'type':f"{i.link_type}",'name':i.name,"owner":i.owner.username,"shared_with":[NewUser.objects.filter(tenant=tenant).filter(username=id.username).first().email for id in i.shared_with.all()],
                'files':[],'folders':[],"expired_date":i.expiry_date,'urlhash':i.link_hash,'password':i.password,'is_favourite':i.is_favourite,'generated_on':i.generated_on,"url":f'https://{tenant}.{FRONT_END_URL}view/link_detail/{i.link_hash}/none',"is_downloadable":i.is_downloadable,'is_proctored':i.is_proctored}
                for files_pk in i.file_hash.all():
                    file=Files_Model.objects.get(pk=files_pk.id)
                    d['files'].append({"name":file.file_name,"urlhash":file.urlhash,'url':file.content.url})
                for folders_pk in i.folder_hash.all():
                    folder=Folder.objects.get(pk=folders_pk.id)
                    d['folders'].append({"name":folder.name,"urlhash":folder.urlhash})
                data.append(d)
            
            return Response(data=data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={"message":f"{e}"},status=status.HTTP_400_BAD_REQUEST)



class Delete_Link(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def delete(self, request):
        try:
            user=get_user_from_tenant(request)
            if 'urlhash' not in request.data:
                return Response(data={'message':'urlhash not in data'},status=status.HTTP_400_BAD_REQUEST)
            objects=Link_Model.objects.filter(link_hash__in=request.data['urlhash'],owner=user)
            objects.update(deleted=True)
            return Response(data={"message":"successfully deleted"},status=status.HTTP_200_OK)
        except Link_Model.DoesNotExist:
            return Response(data={"message": f"link does not exist"},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(data={"message":f'{e}'},status=status.HTTP_400_BAD_REQUEST)





class MoveFolder(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def post(self, request,*args,**kwargs):
        try:
            user=get_user_from_tenant(request)
            if 'file_hash' not in request.data or 'folder_hash' not in request.data or 'move_folder' not in request.data:
                return Response(data={"message":f'file_hash or folder_hash or move_folder not in request.data'},status=status.HTTP_400_BAD_REQUEST)
            if request.data['move_folder'] in request.data['folder_hash']:
                return Response(data={'message':f'Cannot move a folder into same folder'},status=status.HTTP_400_BAD_REQUEST)
            move_folder=get_object_or_None(Folder,urlhash=request.data.get('move_folder'))
            move_folder=move_folder
            for file_hash in request.data['file_hash']:
                file=get_object_or_None(Files_Model,urlhash=file_hash)
                if file.folder==move_folder:
                    return Response(data={"message":f"{file.file_name} already in folder {move_folder}"},status=status.HTTP_400_BAD_REQUEST)
                if not file or file.owner!=user:
                    return Response(data={"message":f"{file_hash} does not exist or you don't have privelages to move folders"},status=status.HTTP_400_BAD_REQUEST)
                Files_Model.objects.filter(pk=file.id).update(folder=move_folder)
            
            for folder_hash in request.data['folder_hash']:
                folder=get_object_or_None(Folder,urlhash=folder_hash)
                if folder.parent==move_folder:
                    return Response(data={"message":f"{folder.name} already in folder {move_folder}"},status=status.HTTP_400_BAD_REQUEST)
                if not folder or folder.owner!=user:
                    return Response(data={"message":f"{folder_hash} does not exist or you don't have privelages to move folders"},status=status.HTTP_400_BAD_REQUEST)
                #delete_keys(upload_path_folder(folder))
                Folder.objects.filter(pk=folder.id).update(parent=move_folder)

            return Response(data={"message":"successfully changed path"},status=status.HTTP_200_OK)
            
        except Exception as e:
            
            return Response(data={"message":f'{e}'}, status=status.HTTP_400_BAD_REQUEST)


class Delete_Multi_Files_Folders(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def delete(self, request, *args, **kwargs):
        try:
            user=get_user_from_tenant(request)
            if 'folder_hash' not in request.data or 'file_hash' not in request.data:
                return Response(data={"message":"folder_hash or file_hash not in request"})
            folders=[]
            files=[]
            for urlhash in request.data['folder_hash']:
                folder=get_object_or_None(Folder,urlhash=urlhash)
                if not folder or folder.owner!=user:
                    internal_share=Internal_Share_Folders.search_parent(user,folder)
                    if internal_share and internal_share.can_add_delete_content:
                        folders.append(folder)
                    else:
                        return Response(data={"message":f"{urlhash} does not exist or you don't have privelages to delete folders'"})
                folders.append(folder)
            
            for urlhash in request.data['file_hash']:
                file=get_object_or_None(Files_Model,urlhash=urlhash)
                if not file or file.owner!=user:
                    internal_share=Internal_Share.objects.filter(file_hash=file,shared_with=user).first()
                    parent=Internal_Share_Folders.search_parent_file(user,file)
                    if internal_share and internal_share.can_add_delete_content:
                        files.append(file)
                    if parent and parent.can_add_delete_content:
                        files.append(file)
                    else:
                        return Response(data={"message":f"{urlhash} does not exist or you don't have privelages to delete file'"})
                files.append(file)  
            for i in files:
                i.link_files.all().delete()
                i.last_deleted=timezone.now()
                i.deleted=True
                i.save()
            for j in folders:
                j.link_folders.all().delete()
                j.last_deleted=timezone.now()
                j.deleted=True
                j.save()
            return Response(data={"message":"success"},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)



class Permenently_Delete(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def delete(self, request, *args, **kwargs):
        try:
            user=get_user_from_tenant(request)
            if 'folder_hash' not in request.data or 'file_hash' not in request.data:
                return Response(data={"message":"folder_hash or file_hash not in request"})
            folders=[]
            files=[]
            for urlhash in request.data['folder_hash']:
                folder=get_object_or_None(Folder,urlhash=urlhash)
                if not folder or folder.owner!=user:
                    return Response(data={"message":f"{urlhash} does not exist or you don't have privelages to delete folders'"})
                folders.append(folder)
            
            for urlhash in request.data['file_hash']:
                file=get_object_or_None(Files_Model,urlhash=urlhash)
                if not file or file.owner!=user:
                    return Response(data={"message":f"{urlhash} does not exist or you don't have privelages to delete file'"})
                files.append(file)  
            for i in files:
                i.delete()
            for j in folders:
                j.delete()
            return Response(data={"message":"success"},status=status.HTTP_200_OK)
        except Exception as e:
            
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)



class Upload_Folder(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def post(self,request,*args,**kwargs):
        try:
            folders_dict={} #dict maintains all keys with urlhash
            user=get_user_from_tenant(request)
            parent_hash=get_object_or_None(Folder,urlhash=request.data['parent_hash'])
            owner=user

            if parent_hash:
                per=Internal_Share_Folders.objects.filter(folder_hash=parent_hash,shared_with=user).first()
                parent=Internal_Share_Folders.search_parent(user,parent_hash)
                if per and per.can_add_delete_content:
                    owner=per.owner
                if parent and parent.can_add_delete_content:
                    owner=parent.owner

            request.data.pop('shared_with')
            request.data.pop('parent_hash')
            request.data.pop('folder_name')
            for i in request.data.keys():
                folder_list=i.split("/")[:-1]
                for j in range(0,len(folder_list)):
                    if folder_list[j] in folders_dict:
                        continue
                    else:
                        curr=folder_list[j]
                        parent_hash=parent_hash if parent_hash else None

                        if j!=0:
                            prev=folder_list[j-1]
                            parent_hash=get_object_or_None(Folder,urlhash=folders_dict[prev])
                        obj=Folder(name=curr,parent=parent_hash,owner=owner)
                        obj.save()
                        folders_dict[curr]=obj.urlhash

        
            for i in request.data.keys():
                folder_list = i.split("/")
                file_name = folder_list[-1]
                parent_folder = get_object_or_None(Folder, urlhash=folders_dict[folder_list[-2]])
                if parent_hash==None:
                    parent_hash='root'
                if type(parent_hash)==str:
                    item_path=owner.username+'/'+parent_hash+'/'+i
                else:
                    item_path=owner.username+'/'+parent_hash.urlhash+'/'+i

                blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
                blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER, blob=item_path)

                try:
                    blob_props = blob_client.get_blob_properties()
                    # blob exists, append data to it
                    blob_client.upload_blob(b'', blob_type="AppendBlob")
                except ResourceNotFoundError:
                    # blob does not exist, create a new one and append data to it
                    blob_client.create_append_blob()
                    blob_client.upload_blob(b'', blob_type="AppendBlob")
                
                # Upload the file in chunks to Azure Blob Storage
                file = request.data[i]
                chunk_size = 100* 1024 * 1024  # 100 MB chunks
                offset = 0
                while True:
                    chunk = file.read(chunk_size)
                    if not chunk:
                        break
                    blob_client.upload_blob(chunk, blob_type="AppendBlob", content_settings=ContentSettings(content_type=file.content_type))
                    offset += len(chunk)
                # Save the file metadata in your Django model
                obj = Files_Model(file_name=file_name, owner=owner, folder=parent_folder)
                obj.content.name = item_path  # Save the URL of the uploaded blob
                obj.save()
                

            return Response(data={"message":"folder created"})
            
        except Exception as e:
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)



class Get_Link_Logs(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def get(self,request,link_hash):
        try:
            user=get_user_from_tenant(request)
            obj=get_object_or_None(Link_Model,link_hash=link_hash,owner=user)
            if obj==None:
                return Response(data={"message":"Link not found"},status=status.HTTP_400_BAD_REQUEST)
            logs=json.loads(obj.logs.first().actions)
            return Response(data=logs,status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)


class Check_Link_Exist(APIView):
    throttle_classes = [UserRateThrottle]
  
    def get(self, request, link_hash):
        try:
            tenant = get_tenant(request)
            request_received_time = timezone.now()
            ten_seconds_later = request_received_time + datetime.timedelta(seconds=30)
            while timezone.now() < ten_seconds_later:
                obj = get_object_or_None(Link_Model, link_hash=link_hash)
                if not obj or obj.deleted:
                    return Response(data={"message": "false"}, status=status.HTTP_400_BAD_REQUEST)
                gevent.sleep(0.1) # sleep for 100ms before checking again
            return Response(data={"message": "true"}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class Deleted_Folder_Details_All(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self,request):
        try:
            user=get_user_from_tenant(request)
            folders=Folder.objects.all().filter(owner=user).filter(deleted=True)
            files=Files_Model.objects.all().filter(owner=user).filter(deleted=True)
            data={"name":"trash","parent":None,"owner":{"email":user.email,"username":user.username},"files":[],"children":[]}
            for i in files:
                data['files'].append({'urlhash':i.urlhash,'name':i.file_name,'owner':i.owner.username,'is_file':True,
                                      'date_created':i.date_uploaded})
            for i in folders:
                data['children'].append({'urlhash':i.urlhash,'name':i.name,'owner':i.owner.username,'is_file':True,
                                      'date_created':i.date_created})
            return Response(data=data,status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)



class Recover_Files_Folders(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def post(self,request):
        try:
            user=get_user_from_tenant(request)
            if 'file_hash' not in request.data or 'folder_hash' not in request.data:
                return Response(data={'message':"file / folder hash not in data"},status=status.HTTP_400_BAD_REQUEST)
            files=Files_Model.objects.filter(urlhash__in=request.data['file_hash'],owner=user)
            folders=Folder.objects.filter(urlhash__in=request.data['folder_hash'],owner=user)
            
            files.update(deleted=False)
            folders.update(deleted=False)
            
            return Response(data={'message':'successfully recovered'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)




class Request_File_Create(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def post(self,request):
        try:
            user=get_user_from_tenant(request)
            tenant=get_tenant(request)
            request.data['user_from']=user.id
            request.data['user_to']=NewUser.objects.get(tenant=tenant,email=request.data['user_to']).id
            if request.data['user_from']==request.data['user_to']:
                return Response(data={"message":"error cant request file to oneself"},status=status.HTTP_400_BAD_REQUEST)
            sz=Request_File_Serializer(data=request.data)
            if sz.is_valid():
                obj=sz.save()
                return Response(data={"message":'request created'},status=status.HTTP_200_OK)
            return Response(data=sz.errors,status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(data={"message":str(e)},status=status.HTTP_400_BAD_REQUEST)
        
    def delete(self,request,urlhash):
        try:
            tenant=get_tenant(request)
            r=Request_File.objects.get(request_hash=urlhash)
            if r:
                r.delete()
                return Response('successfully redacted request',status=status.HTTP_200_OK)
        except Exception as e:
            return Response(f'{e}',status=status.HTTP_400_BAD_REQUEST)
        


class Request_File_Upload(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def post(self,request,urlhash):
        try:
            tenant=get_tenant(request)
            r=Request_File.objects.get(request_hash=urlhash)
            serializer=FileSerializer(data=request.data)
            if serializer.is_valid():
                serializer.validated_data['folder']=None
                serializer.validated_data['owner']=NewUser.objects.get(username=r.user_from,tenant=tenant)
                obj=serializer.save()
                r.delete()
                return Response('successfully uploaded file',status=status.HTTP_200_OK)
        except Exception as e:
            return Response(f'{e}',status=status.HTTP_400_BAD_REQUEST)







class Internal_File_Notification(APIView):
    #authentication_classes = [JWTauthentication]
    #permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def post(self,request,file_hash):
        try:
            file=Files_Model.objects.get(urlhash=file_hash)
            owner=file.owner
            time=timezone.now()
            create_notifications(owner,extras=f'suspicious activity detected on file-{file.file_name} on {time}')
            return Response('successfully got data',status=status.HTTP_200_OK)
        except Exception as e:
            
            return Response(data={"message":f'{e}'},status=status.HTTP_400_BAD_REQUEST)



class Link_Count_Dashboard(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def get(self,request):
        try:
            user=get_user_from_tenant(request)
            all_links=Link_Model.objects.filter(owner=user).all()
            total_links=len(all_links)
            active_links=0
            now=timezone.now()
            for i in all_links:
                if i.expiry_date and i.expiry_date<now or (i.deleted):
                    continue
                else:
                    active_links+=1
            return Response({"expired_link":total_links-active_links,'total_link':total_links,'active_links':active_links})
        except Exception as e:
            return Response(data={'message':f'{e}'},status=status.HTTP_400_BAD_REQUEST)


class Recently_Acessed(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self,request,link_hash):
        try:
            user=get_user_from_tenant(request)
            folder=get_object_or_None(Folder,urlhash=link_hash)
            file=get_object_or_None(Files_Model,urlhash=link_hash)
            recently_accessed=user.recently_accessed
            if file:
                recently_accessed.append({'hash':link_hash,'type':'file','link':file.content.url})
            if folder:
                recently_accessed.append(json.dumps({'hash':link_hash,'type':'folder'}))
            if len(recently_accessed)>4:
                user.recently_accessed=recently_accessed[1:]
            user.save()
            return Response({"message":'Success'},status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message':f'{e}'},status=status.HTTP_400_BAD_REQUEST)



class Recently_Acessed_Get(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self,request):
        try:
            user=get_user_from_tenant(request)
            recently_accessed=user.recently_accessed
            return Response(json.dumps(recently_accessed),status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message':f'{e}'},status=status.HTTP_400_BAD_REQUEST)


class Storage_Share(APIView):
    authentication_classes=[JWTauthentication]
    permissions=[IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self,request):
        try:
            user=get_user_from_tenant(request)
            all_files=user.files.all()
            d={}
            total=user.storage_amount_used
            for i in all_files:
                file_ext=i.file_name.split('.')
                ext=file_ext[-1]
                size=float(i.filesize_gb)
                if ext not in d:
                    d[ext]=0
                    d[ext]+=size
                d[ext]+=size
            d['total']=total
            d['available']=user.total_available_space()-d['total']
    
            for i in d.keys():
                d[i]=d[i]/(user.total_available_space())*100

            d['total_gb']=total
            d['available_gb']=user.total_available_space()


            return Response(data=d,status=status.HTTP_200_OK)

        except Exception as e:
            return Response(data={'message':f'{e}'},status=status.HTTP_400_BAD_REQUEST)



class Approve_Link(APIView):
    throttle_classes = [UserRateThrottle]

    def post(self,request,urlhash):
        try:
            link=Link_Model.objects.get(link_hash=urlhash)
            if request.data['1xyz3wrt']==99:
                link.is_approved=True
                link.save()
            return Response(data={'message':'Link approved'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response({"message":str(e)},status=status.HTTP_400_BAD_REQUEST)


def send_file(request,urlhash):
    img = open('logo.png.png', 'rb')
    link=Link_Model.objects.get(link_hash=urlhash)
    link.is_approved=False
    user=link.owner
    create_notifications(user,f'Your sent email for link {link.name} was accessed')
    link.save()
    response = FileResponse(img)
    response['Pragma']='no-cache'
    return response



class Sos_Link(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def post(self,request):
        try:
            user=get_user_from_tenant(request)
            all_links=Link_Model.objects.filter(owner=user).all()
            all_links.update(deleted=True)
            return Response(data={'message':'successfully deleted all links'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'message':str(e)},status=status.HTTP_400_BAD_REQUEST)

class Links_By_Date(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]

    def get(self, request):
        try:
            user = get_user_from_tenant(request)
            today = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
            week_start = today - datetime.timedelta(days=today.weekday())
            week_end = week_start + datetime.timedelta(days=6)
            all_links = Link_Model.objects.filter(owner=user, generated_on__range=[week_start, week_end])
            user_timezone = pytz.timezone(TIME_ZONE)
            data = {i: 0 for i in range(7)}
            for link in all_links:
                link_date = link.generated_on.astimezone(pytz.utc).astimezone(user_timezone).date()
                data[link_date.weekday()] += 1
            return Response(data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)

            
            
            
class Remove_Shared(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def delete(self, request, *args, **kwargs):
        try:
            user=get_user_from_tenant(request)
            if 'folder_hash' not in request.data or 'file_hash' not in request.data:
                return Response(data={"message":"folder_hash or file_hash not in request"})
            for urlhash in request.data['folder_hash']:
                folder=get_object_or_None(Folder,urlhash=urlhash)
                if not folder :
                    return Response(data={"message":f"{urlhash} does not exist or you don't have privelages to delete folders'"})
                print(folder)
                all_shares=Internal_Share_Folders.objects.get(shared_with=user,folder_hash=folder)
                print(all_shares)
                all_shares.delete()
            
            for urlhash in request.data['file_hash']:
                file=get_object_or_None(Files_Model,urlhash=urlhash)
                print(file)
                if not file:
                    return Response(data={"message":f"{urlhash} does not exist or you don't have privelages to delete file'"})
                all_shares=Internal_Share.objects.get(shared_with=user,file_hash=file)
                print(all_shares)
                all_shares.delete()
    
            return Response(data={"message":"success"},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)
            
            
class SearchBar(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self, request,type,query):
        try:
            user=get_user_from_tenant(request)
            tenant=user.tenant
            query=query.lower()
            if type=='link':
                all_obj=Link_Model.objects.filter(name__contains=query,owner=user,deleted=False).all()
                sz=Detail_Link_Serializer(all_obj,many=True)
                return Response({'data':sz.data}, status=status.HTTP_200_OK)
            if type=='file':
                all_obj=Files_Model.objects.filter(file_name__contains=query,owner=user).all()
                sz=DetailFileSerializer(all_obj,many=True)
                return Response({'data':sz.data}, status=status.HTTP_200_OK)
            if type=='folder':
                all_obj=Folder.objects.filter(name__contains=query,owner=user).all()
                sz=DetailFolderSerializer(all_obj,many=True)
                return Response({'data':sz.data}, status=status.HTTP_200_OK)
            if type=='user':
                all_obj=NewUser.objects.filter(username__contains=query,email__contains=query,tenant=tenant).all()
                sz=UserSerializer(all_obj,many=True)

                return Response({'data':sz.data}, status=status.HTTP_200_OK)
            if type=='groups':
                groups = Group_Permissions.objects.filter(user=user).values_list('group', flat=True)
                people_groups = People_Groups.objects.filter(id__in=groups,name__contains=query)
                sz=DetailGroupSerializer(people_groups,many=True)
                return Response({'data':sz.data}, status=status.HTTP_200_OK)
            if type=='internalshare':
                user2=NewUser.objects.filter(username__contains=query).first()
                files=Internal_Share.objects.filter(owner=user,shared_with=user2).values_list('file_hash', flat=True)
                folders=Internal_Share_Folders.objects.filter(owner=user,shared_with=user2).values_list('folder_hash', flat=True)
                files=Files_Model.objects.filter(id__in=files)
                folders=Folder.objects.filter(id__in=folders)
                sz=DetailFileSerializer(files,many=True)
                sz2=DetailFolderSerializer(folders,many=True)
                data={}      
                data['files']=sz.data   
                data['folder']=sz2.data    
                return Response({'data':data}, status=status.HTTP_200_OK)
            return Response({'detail': 'Invalid Input.'}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
             return Response({'detail': f'{str(e)}'}, status=status.HTTP_400_BAD_REQUEST)





class Add_Link_Favourite(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def put(self, request, link_hash):
        try:
            user=get_user_from_tenant(request)
            link=Link_Model.objects.get(link_hash=link_hash)
            link.is_favourite= not link.is_favourite
            link.save()
    
            return Response(data={"message":"success"},status=status.HTTP_200_OK)
        except Exception as e:
            
            return Response(data={"message":{e}},status=status.HTTP_400_BAD_REQUEST)
        

        
class MediaStreamView(APIView):
    CHUNK_SIZE = 1024 * 1024  # 1 MB
    def _stream_blob(self, blob_client, start=0, length=None):
        stream = blob_client.download_blob(offset=start, length=length)
        while True:
            data = stream.read(self.CHUNK_SIZE)
            if not data:
                break
            yield data
    def get(self, request, token):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256',])
            ip=get_client_ip(request)
            if ip!=payload['ip']:
                return Response(data={'message':'Invalid Request'},status=status.HTTP_400_BAD_REQUEST)
            connection_string = AZURE_CONNECTION_STRING
            blob_service_client = BlobServiceClient.from_connection_string(connection_string)
            container_client = blob_service_client.get_container_client(AZURE_CONTAINER)
            urlhash = payload['hash']
            obj = Files_Model.objects.get(urlhash=urlhash)
            blob_name = obj.content.name
            blob_client = container_client.get_blob_client(blob_name)

            content_type, encoding = mimetypes.guess_type(blob_name)
            if not content_type:
                content_type = 'application/octet-stream'

            blob_properties = blob_client.get_blob_properties()
            content_length = blob_properties.size

            if 'Range' in request.headers:
                start, end = request.headers['Range'].split('=')[1].split('-')
                start = int(start)
                if not end:
                    end = content_length - 1

                end = int(end)
                length = end - start + 1
                blob_range = 'bytes={}-{}'.format(start, end)
                resp = StreamingHttpResponse(self._stream_blob(blob_client, start, length), status=206, content_type=content_type)
                resp['Content-Length'] = str(length)
                resp['Content-Range'] = 'bytes %s-%s/%s' % (start, end, content_length)
            else:
                resp = StreamingHttpResponse(self._stream_blob(blob_client), status=206, content_type=content_type)
                resp['Content-Length'] = content_length
            return resp
        except Exception as e:
            return Response(data={'message': 'Invalid Request'}, status=status.HTTP_400_BAD_REQUEST)
                     





class Get_File_Detail(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def get(self,request,obj_hash,file_hash,type):
        try:
            user=get_user_from_tenant(request)
            if type=='group':
                obj=Files_Model.objects.get(urlhash=file_hash)
                grp=People_Groups.objects.filter(group_hash=obj_hash,files__in=[obj]).first()
                if not grp:
                    grp=People_Groups.search_parent_file(obj_hash,obj)
                grp_per=Group_Permissions.objects.filter(group=grp,user=user)[0]
                if grp:
                    data={"urlhash":obj.urlhash,"name":obj.file_name,"url":f'{BACKEND_URL}api/content/media/{create_media_jwt(obj,get_client_ip(request))}',
                    "size":str(int(obj.content.size/1024))+" kb","owner":obj.owner.username,
                    "date_created":str(obj.date_uploaded)[0:11],'is_file':True,
                    'can_add_delete_content':grp_per.can_add_delete_content,
                    'can_share_content':grp_per.can_share_content,
                    'can_download_content':grp_per.can_download_content,'is_proctored':grp_per.is_proctored,'download_link':download_url_generate_sas(obj,get_client_ip(request)) if grp_per.can_download_content else None}
                return Response(data=data,status=status.HTTP_200_OK)

            if type=='internal_share':
                obj=Files_Model.objects.get(urlhash=file_hash)
                internal_share=Internal_Share.objects.filter(file_hash=obj,shared_with=user).first()
                if not internal_share:
                    internal_share=Internal_Share_Folders.search_parent_file(user,obj)
                data={"urlhash":obj.urlhash,"name":obj.file_name,"url":f'{BACKEND_URL}api/content/media/{create_media_jwt(obj,get_client_ip(request))}',
                    "size":str(int(obj.content.size/1024))+" kb","owner":obj.owner.username,
                    "date_created":str(obj.date_uploaded)[0:11],'is_file':True,'is_downloadable':internal_share.is_downloadable,
                    'can_add_delete_content':internal_share.can_add_delete_content,
                    'can_share_content':internal_share.can_share_content,
                    'can_download_content':internal_share.can_download_content,'is_proctored':internal_share.is_proctored,'download_link':download_url_generate_sas(obj,get_client_ip(request)) if internal_share.can_download_content else None}
                return Response(data=data,status=status.HTTP_200_OK)
            if type=='home':
                obj=Files_Model.objects.get(owner=user,urlhash=file_hash)
                data={"urlhash":obj.urlhash,"name":obj.file_name,"url":f'{BACKEND_URL}api/content/media/{create_media_jwt(obj,get_client_ip(request))}',"size":str(int(obj.content.size/1024))+" kb","owner":obj.owner.username,"date_created":str(obj.date_uploaded)[0:11],'is_file':True,
                    'download_link':download_url_generate_sas(obj,get_client_ip(request))}
                return Response(data=data,status=status.HTTP_200_OK)
            return Response(data={'message':'Invalid Request'},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            print(e)
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)
        
class Get_File_Link_Detail(APIView):
    throttle_classes = [UserRateThrottle]
    def get(self,request,obj_hash,file_hash,type):
        try:
            if type=='link':
                link=Link_Model.objects.get(link_hash=obj_hash)
                obj=Files_Model.objects.get(urlhash=file_hash)
                if link.is_drm:
                    key=f'{obj.urlhash}_{link.link_hash}_video'
                    if cache.get(key):
                        status_=get_video_status(obj)
                        if status_:
                            url=get_video_otp(obj)
                            data={"urlhash":obj.urlhash,"name":obj.file_name,"url":url,
                                  "size":str(int(obj.content.size/1024))+" kb","owner":obj.owner.username,
                                  "date_created":str(obj.date_uploaded)[0:11],'is_file':True,'can_download_content':link.is_downloadable,
                                  'is_proctored':link.is_proctored,'is_drm':link.is_drm,'download_link':download_url_generate_sas(obj,get_client_ip(request)) if link.is_downloadable else None}
                            return Response(data=data,status=status.HTTP_200_OK)
                        data={"urlhash":obj.urlhash,"name":obj.file_name,"message":'security is being prepared please wait',
                                  "size":str(int(obj.content.size/1024))+" kb","owner":obj.owner.username,
                                  "date_created":str(obj.date_uploaded)[0:11],'is_file':True,'can_download_content':link.is_downloadable,
                                  'is_proctored':link.is_proctored,'is_drm':link.is_drm,'download_link':download_url_generate_sas(obj,get_client_ip(request)) if link.is_downloadable else None}
                        return Response(data=data,status=status.HTTP_200_OK)
                    else:
                        upload_video_to_vdocipher(obj.urlhash,link.link_hash)
                        data={"urlhash":obj.urlhash,"name":obj.file_name,"message":'security is being prepared please wait',
                                  "size":str(int(obj.content.size/1024))+" kb","owner":obj.owner.username,
                                  "date_created":str(obj.date_uploaded)[0:11],'is_file':True,'can_download_content':link.is_downloadable,
                                  'is_proctored':link.is_proctored,'is_drm':link.is_drm,'download_link':download_url_generate_sas(obj,get_client_ip(request)) if link.is_downloadable else None}
                        return Response(data=data,status=status.HTTP_200_OK)


                else:

                    data={"urlhash":obj.urlhash,"name":obj.file_name,"url":f'{BACKEND_URL}api/content/media/{create_media_jwt(obj,get_client_ip(request))}',
                        "size":str(int(obj.content.size/1024))+" kb","owner":obj.owner.username,
                        "date_created":str(obj.date_uploaded)[0:11],'is_file':True,'can_download_content':link.is_downloadable,
                        'is_drm':link.is_drm,'is_proctored':link.is_proctored,'download_link':download_url_generate_sas(obj,get_client_ip(request)) if link.is_downloadable else None}
                    return Response(data=data,status=status.HTTP_200_OK)


            return Response(data={"message":"success"},status=status.HTTP_200_OK)
        except Exception as e:
            print(e)
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)
        

class Download_Folder_View(APIView):
    throttle_classes = [UserRateThrottle]

    def member_files(self,blob_names,blob_service_client):
        modified_at = datetime.datetime.now()
        perms = 0o600
        for blob_name in blob_names:
                blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER, blob=blob_name[0])
                yield (blob_name[1], modified_at, perms, ZIP_32, self.blob_chunk_generator(blob_client))

    def blob_chunk_generator(self,blob_client):
        blob_size = blob_client.get_blob_properties().size
        offset = 0
        chunk_size = 1024*1024*10
        while True:
            if offset >= blob_size:
                break
            data = blob_client.download_blob(offset=offset, length=chunk_size)
            chunk = data.readall()
            if not chunk:
                break
            offset += len(chunk)
            try:
                yield chunk
            except UnicodeDecodeError:
                yield chunk

    def get(self,request,token):
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256',])
            ip=get_client_ip(request)
            if ip!=payload['ip']:
                return Response(data={'message':'Invalid Request'},status=status.HTTP_400_BAD_REQUEST)
            obj=Folder.objects.get(urlhash=payload['hash'])
            _,files=obj.get_subfolders_and_files()
            blob_path=obj.give_string_path()
            blob_service_client = BlobServiceClient.from_connection_string(conn_str=AZURE_CONNECTION_STRING)
            blob_client = blob_service_client.get_container_client(AZURE_CONTAINER)
            blob_names = [(i.content.name,i.order_path()) for i in files]
            name=blob_path.split('/')[-2]
            response = StreamingHttpResponse(stream_zip(self.member_files(blob_names,blob_service_client),chunk_size=1024*1024*10),content_type='application/zip')
            response['Content-Disposition'] = f'attachment; filename="{name}.zip"'
            return response
        except Exception as e:
            print(e)            
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)



class Download_Multi_File_Folder(APIView):
    #authentication_classes = [JWTauthentication]
    #permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def member_files(self,blob_names,blob_service_client):
        modified_at = datetime.datetime.now()
        perms = 0o600
        for blob_name in blob_names:
                blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER, blob=blob_name[0])
                yield (blob_name[1], modified_at, perms, ZIP_32, self.blob_chunk_generator(blob_client))

    def blob_chunk_generator(self,blob_client):
        blob_size = blob_client.get_blob_properties().size
        offset = 0
        chunk_size = 1024*1024*10
        while True:
            if offset >= blob_size:
                break
            data = blob_client.download_blob(offset=offset, length=chunk_size)
            chunk = data.readall()
            if not chunk:
                break
            offset += len(chunk)
            try:
                yield chunk
            except UnicodeDecodeError:
                yield chunk

    def post(self,request,type):
        try:
            payload=jwt.decode(request.data['token'],SECRET_KEY,algorithms=['HS256',])
            username=payload['username']
            user=NewUser.objects.get(username=username)
            tenant=get_tenant(request)
            blob_names=[]
            if type=='home':
                files_hash=request.data['file_hash'].split(',')
                folders_hash=request.data['folder_hash'].split(',')
                print(files_hash,folders_hash)
                #added
                for i in files_hash:
                    obj=Files_Model.objects.filter(urlhash=i).first()
                    if not obj:
                        continue
                    if obj.owner!=user:
                        return Response(data={'message':'Invalid Request'},status=status.HTTP_400_BAD_REQUEST)
        
                    blob_names.append((obj.content.name,obj.order_path()))
                for j in folders_hash:
                    obj=Folder.objects.filter(urlhash=j).first()
                    if not obj:
                        continue
                    if obj.owner!=user:
                        return Response(data={'message':'Invalid Request'},status=status.HTTP_400_BAD_REQUEST)
                    _,files=obj.get_subfolders_and_files()
                    
                    blob_names.extend([(i.content.name,i.order_path()) for i in files])
            if type=='internal':
                files_hash=request.data['file_hash'].split(',')
                folders_hash=request.data['folder_hash'].split(',')
                for i in files_hash:
                    file=Files_Model.objects.filter(urlhash=i).first()
                    obj=Internal_Share.objects.filter(file_hash=file,shared_with=user).first()
                    if file and not obj:
                        obj=Internal_Share_Folders.search_parent_file(user,file)
                    if not obj:
                        continue
                    if obj and  not obj.can_download_content :
                        return Response(data={'message':'Invalid Request'},status=status.HTTP_400_BAD_REQUEST)
                    blob_names.append((obj.file_hash.content.name,obj.file_hash.order_path()))
                for j in folders_hash:
                    folder=Folder.objects.filter(urlhash=j).first()
                    obj=Internal_Share_Folders.objects.filter(folder_hash=folder,shared_with=user).first()
                    if folder and not obj:
                        obj=Internal_Share_Folders.search_parent(user,folder)
                    if not obj:
                        continue
                    if obj and not obj.can_download_content:
                        return Response(data={'message':'Invalid Request'},status=status.HTTP_400_BAD_REQUEST)
                    _,files=obj.folder_hash.get_subfolders_and_files()
                    blob_names.extend([(i.content.name,i.order_path()) for i in files])
            if type=='group':
                group_hash=request.data['group_hash']
                files_hash=request.data['file_hash'].split(',')
                folders_hash=request.data['folder_hash'].split(',')
                print(files_hash,folders_hash)
                for i in files_hash:
                    obj=Files_Model.objects.filter(urlhash=i).first()
                    if not obj:
                        continue
                    grp=People_Groups.objects.filter(files__in=[obj],group_hash=group_hash).first()
                    if not grp:
                        grp=People_Groups.search_parent_file(group_hash,obj)
                    if grp and grp.is_downloadable:
                        blob_names.append((obj.content.name,obj.order_path()))
                for j in folders_hash:
                    obj=Folder.objects.filter(urlhash=j).first()
                    if not obj:
                        continue
                    grp=People_Groups.objects.filter(folders__in=[obj],group_hash=group_hash).first()
                    if not grp:
                        grp=People_Groups.search_parent(group_hash,obj)
                    if grp and grp.is_downloadable:
                        _,files=obj.get_subfolders_and_files()
                        blob_names.extend([(i.content.name,i.order_path()) for i in files])


            blob_service_client = BlobServiceClient.from_connection_string(conn_str=AZURE_CONNECTION_STRING)
            blob_client = blob_service_client.get_container_client(AZURE_CONTAINER)
            name=f'{user.username}_{timezone.now()}'
            response = StreamingHttpResponse(stream_zip(self.member_files(blob_names,blob_service_client),chunk_size=1024*1024*10),content_type='application/zip')
            response['Content-Disposition'] = f'attachment; filename="{name}.zip"'
            return response
        except Exception as e:
            print(e)            
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)
        


class Download_Multi_File_Folder_Link(APIView):
    authentication_classes = [JWTauthentication]

    def member_files(self,blob_names,blob_service_client):
        modified_at = datetime.datetime.now()
        perms = 0o600
        for blob_name in blob_names:
                blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER, blob=blob_name[0])
                yield (blob_name[1], modified_at, perms, ZIP_32, self.blob_chunk_generator(blob_client))

    def blob_chunk_generator(self,blob_client):
        blob_size = blob_client.get_blob_properties().size
        offset = 0
        chunk_size = 1024*1024*10
        while True:
            if offset >= blob_size:
                break
            data = blob_client.download_blob(offset=offset, length=chunk_size)
            chunk = data.readall()
            if not chunk:
                break
            offset += len(chunk)
            try:
                yield chunk
            except UnicodeDecodeError:
                yield chunk

    def post(self,request):
        try:
            blob_names=[]
            link_hash=request.data['link_hash']
            files_hash=request.data['file_hash']
            folders_hash=request.data['folder_hash']
            
            for i in files_hash:
                obj=Files_Model.objects.get(urlhash=i)
                link=Link_Model.objects.filter(file_hash__in=[obj],link_hash=link_hash).first()
                if not link:
                    link=Link_Model.search_parent_file(link_hash,obj)
                if link and link.is_downloadable:
                    blob_names.append((obj.content.name,obj.order_path()))
            for j in folders_hash:
                obj=Folder.objects.get(urlhash=j)
                link=Link_Model.objects.filter(folder_hash__in=[obj],link_hash=link_hash).first()
                if not link:
                    link=Link_Model.search_parent(link_hash,obj)
                if link and link.is_downloadable:
                    _,files=obj.get_subfolders_and_files()
                    blob_names.extend([(i.content.name,i.order_path()) for i in files])

            blob_service_client = BlobServiceClient.from_connection_string(conn_str=AZURE_CONNECTION_STRING)
            blob_client = blob_service_client.get_container_client(AZURE_CONTAINER)
            name=f'{timezone.now()}'
            response = StreamingHttpResponse(stream_zip(self.member_files(blob_names,blob_service_client),chunk_size=1024*1024*10),content_type='application/zip')
            response['Content-Disposition'] = f'attachment; filename="{name}.zip"'
            return response
        except Exception as e:
            print(e)            
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)