from lib2to3.pgen2 import token
from os import access
from django.shortcuts import render
from Varency.settings import CLIENT_ID,CLIENT_SECRET,REDIRECT_URI,FRONT_END_URL,AZURE_CONNECTION_STRING,AZURE_CONTAINER
from files.sub_utils import get_user_from_tenant
from files.utils import get_user,get_token
from ftp.models import Server_Connection
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from files.jwt_utils import JWTauthentication
from content.models import Folder
from .serializers import ServerSerializer,SyncDirectionSerializer,SyncDirectionSerializer2
from files.models import NewUser
from .utils import check_and_refresh_googledrive,get_access_token_from_code_googledrive,check_and_refresh_token_onedrive,get_authorize_url,get_authorize_url_onedrive,get_access_token_from_code
from oauth2client.client import  OAuth2WebServerFlow
import requests
import json
from urllib.parse import unquote
from django.shortcuts import redirect
from rest_framework.throttling import UserRateThrottle
import subprocess
from django.core.cache import cache
import os 
import signal
from django.core.cache import cache





class Create_Remote_Server(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def post(self,request, *args, **kwargs):
        try:
            data=request.data
            sz=ServerSerializer(data=data)
            user=get_user_from_tenant(request)
            if sz.is_valid():
                obj=sz.save(sz.validated_data,user,'googledrive')
                return Response(data={"message":'server created','url':get_authorize_url(request,obj.server_name,user.username)},status=status.HTTP_200_OK)
            else:
                return Response(data={'message':sz.errors},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(data={'message':str(e)},status=status.HTTP_400_BAD_REQUEST)

class Create_Remote_Server_OneDrive(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def post(self,request, *args, **kwargs):
        try:
            sz=ServerSerializer(data=request.data)
            user=get_user_from_tenant(request)
            if sz.is_valid():
                obj=sz.save(sz.validated_data,user,'onedrive')
                return Response(data={"message":'server created','url':get_authorize_url_onedrive(request,obj.server_name,user.username)},status=status.HTTP_200_OK)
            else:
                return Response(data={'message':sz.errors},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(data={'message':str(e)},status=status.HTTP_400_BAD_REQUEST)





class Get_User_Servers(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self,request,*args, **kwargs):
        try:
            user=get_user_from_tenant(request)
            if user:
                sz=ServerSerializer(user.servers.all(),many=True)
                return Response(sz.data,status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)


class Create_Sync_Direction(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def post(self,request,*args, **kwargs):
        try:
            sz=SyncDirectionSerializer2(data=request.data)
            folder_to_id=request.data['folder_to_id']
            if sz.is_valid():
                folder=Folder.objects.filter(urlhash=folder_to_id).first()
                if folder:
                    if folder.owner!=request.user:
                        return Response(data={'message':"You don't have privelages to access this folder"},status=status.HTTP_400_BAD_REQUEST)
                obj=sz.save()

                return Response(data={"message":'server sync created'},status=status.HTTP_200_OK)
            return Response(data={'message':"\n".join([f"{key}: {value}" for key, value in sz.errors.items()])},status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)
        



class Post_Code(APIView):
    throttle_classes = [UserRateThrottle]

    def get(self,request):
        try:
            arr=request.GET['state'].split('_')
            server_name=arr[0]
            username=arr[1]
            user=NewUser.objects.get(username=username)
            code=request.GET['code']
            token=get_access_token_from_code_googledrive(request,code)
            obj=Server_Connection.objects.filter(server_name=server_name).first()
            obj.user_token=token
            obj.save()
            return Response(status=302, headers={'location': f'http://{user.tenant.subdomain}.{FRONT_END_URL}integrations/server/googledrive'})

        except Exception as e:
            
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)



class Get_Code_Access_From_Server(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def get(self,request,server_name):
        try:
        
            obj=Server_Connection.objects.filter(server_name=server_name).first()
            token_detail=json.loads(obj.user_token)
            
            access_token=token_detail['access_token']
            refreshToken=token_detail['refresh_token']
            
            token,changed=check_and_refresh_token_onedrive(request,access_token,refreshToken)
            if changed:
                token_detail=token
                obj.user_token=token
                obj.save()
                token_detail=json.loads(token)
            return Response(data={'token':token_detail['access_token']},status=status.HTTP_200_OK)
        except Exception as e:
            
            return Response(data={"message":{str(e)}},status=status.HTTP_400_BAD_REQUEST)


class List_Google_Folders(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    def get(self,request,server_name,id):
        try:
            obj=Server_Connection.objects.filter(server_name=server_name).first()
            token=obj.user_token
            mimeType =f"application/vnd.google-apps.folder"
            api_end_point=f"https://www.googleapis.com/drive/v2/files/?access_token={token['access_token']}"
            print(api_end_point)
            payload={'q':mimeType}
            r=requests.get(api_end_point,data=payload)
            print(r.text)
            return Response(data={'message':'success'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={'message':{str(e)}},status=status.HTTP_400_BAD_REQUEST)

class Delete_Server(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def delete(self,request,server_name):
        try:
            obj=Server_Connection.objects.filter(server_name=server_name).first()
            
            obj.delete()
            return Response(data={'message':'deleted server'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={'message':{str(e)}},status=status.HTTP_400_BAD_REQUEST)




class Post_Code_OneDrive(APIView):
    throttle_classes = [UserRateThrottle]
    def get(self,request):
        try:
            arr=request.GET['state'].split('_')
            server_name=arr[0]
            username=arr[1]
            user=NewUser.objects.get(username=username)
            code=request.GET['code']
            token=get_access_token_from_code(request,code)
            obj=Server_Connection.objects.filter(server_name=server_name).first()
            obj.user_token=token
            obj.save()
            return Response(status=302, headers={'location': f'http://{user.tenant.subdomain}.{FRONT_END_URL}integrations/server/onedrive'})
        except Exception as e:
            return Response(data={'message':{str(e)}},status=status.HTTP_400_BAD_REQUEST)




class List_One_Drive(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]

    
    def get_folder_name(self,folder_id, access_token):
    
        url = f"https://graph.microsoft.com/v1.0/me/drive/items/{folder_id}"
        headers = {
            "Authorization": "Bearer " + access_token,
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
           
            data = response.json()
            return data["name"]
        else:
            raise Exception(f"Error: {response.text}")

    def get_folder_children(self,folder_id, access_token):
            url = f"https://graph.microsoft.com/v1.0/me/drive/items/{folder_id}/children"
            headers = {
                "Authorization": "Bearer " + access_token,
                "Content-Type": "application/json"
            }
            response = requests.get(url, headers=headers)
            count=0
            if response.status_code == 200:
                data = response.json()
                children = []
                for item in data["value"]:
                    
                        if len(item['name'].split('.')) > 1:
                            count+=1
                            continue
                        child={}
                        child['urlhash']=item['id']
                        child['name']=item['name']
                        children.append(child)
                return children,count
            else:
                raise Exception(f"Error: {response.text}")

    def get(self,request,server_name,id):
        try:
            server=Server_Connection.objects.get(server_name=server_name)
            token_detail=json.loads(server.user_token)
            access_token=token_detail['access_token']
            refreshToken=token_detail['refresh_token']
            token,changed=check_and_refresh_token_onedrive(request,access_token,refreshToken)
            if changed:
                token_detail=token
                server.user_token=token
                server.save()
            if type(token_detail)==str:
                token_detail=json.loads(token_detail)
            children,count=self.get_folder_children(id,token_detail['access_token'])
            

            return Response(data={'children':children,'parent':id,'name':self.get_folder_name(id,token_detail['access_token']),'file_count':count},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={'message':{str(e)}},status=status.HTTP_400_BAD_REQUEST)
        


class Start_Sync(APIView):
    authentication_classes = [JWTauthentication]
    permissions = [IsAuthenticated]
    throttle_classes = [UserRateThrottle]
    def get(self,request,server_name):
        try:
            user=get_user_from_tenant(request)
            obj=Server_Connection.objects.filter(server_name=server_name).first()
            name=f'{user.username}_{obj.server_name}'
            if cache.has_key(name):
                pid = cache.get(name)
                if pid and os.path.exists(f"/proc/{pid}"):
                    os.kill(pid, signal.SIGTERM)
                cache.delete(name)

            #subprocess.run(["pkill", "-f", f"{user.username}_{obj.server_name}"])
            for j in obj.connection_syncs.all():
                    username=user.username
                    folder_to_id=j.folder_to_id.urlhash
                    folder_id=j.folder_from_id
                    token_detail=json.loads(obj.user_token)
                    type_=obj.type
                    if type_=='onedrive':
                        token_changed,changed=check_and_refresh_token_onedrive('str',token_detail['access_token'],token_detail['refresh_token'])
                        if not changed:
                            access_token=token_detail['access_token']
                        if changed:
                            token_changed_=json.loads(token_changed)
                            access_token=token_changed_['access_token']
                            obj.user_token=token_changed
                            obj.save()
                    else:
                        token,changed=check_and_refresh_googledrive(request,token_detail['access_token'],token_detail['refreshToken'])
                        if changed:
                            token_detail=token
                        if type(token_detail)==str:
                            token_detail=json.loads(token_detail)
                    
                    command = ["python3", "ftp/sync.py",folder_id,folder_to_id,username,access_token,AZURE_CONNECTION_STRING,AZURE_CONTAINER,type_]
                    #hi
                    process = subprocess.Popen(command, stdout=subprocess.PIPE)
                    cache.set(name, process.pid)

            
            return Response(data={'message':'Sync started'},status=status.HTTP_200_OK)
        except Exception as e:
            return Response(data={'message':{str(e)}},status=status.HTTP_400_BAD_REQUEST)




class List_Google_Drive_Folders(APIView):
    authentication_classes = [JWTauthentication]
    permission_classes = [IsAuthenticated]

    def get_folder_name(self, folder_id, access_token):
        if folder_id=='root':
            url='https://www.googleapis.com/drive/v3/files'
        else:
            url = f"https://www.googleapis.com/drive/v3/files?q='{folder_id}' in parents"
        headers = {
            "Authorization": "Bearer " + access_token,
            "Content-Type": "application/json"
        }
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data["name"]
        else:
            raise Exception(f"Error: {response.text}")

    def get_folder_children(self, folder_id, access_token):
        print(folder_id,access_token)
        if folder_id=='root':
            url='https://www.googleapis.com/drive/v3/files'
        else:
            url = f"https://www.googleapis.com/drive/v3/files?q='{folder_id}' in parents"
        headers = {
            "Authorization": "Bearer " + access_token,
            "Content-Type": "application/json"
        }
        params = {
                 "fields": "id,name",
            }

        response = requests.get(url, headers=headers,params=params)
        print(response)
        if response.status_code == 200:
            data = response.json()
            children = []
            count=0
            for item in data["files"]:
                if item["mimeType"] == "application/vnd.google-apps.folder":
                    child = {}
                    child['urlhash'] = item['id']
                    child['name'] = item['name']
                    children.append(child)
                else:
                    count+=1
            return children,count
        else:
            raise Exception(f"Error: {response.text}")

    def get(self, request, server_name,id):
        try:
            server=Server_Connection.objects.get(server_name=server_name)
            if type(server.user_token)==str:
                token_detail=json.loads(server.user_token)
            else:
                token_detail=server.user_token
            access_token=token_detail['access_token']
            refreshToken=token_detail['refresh_token']
            token,changed=check_and_refresh_googledrive(request,access_token,refreshToken)
            if changed:
                token_detail['access_token']=token
                server.user_token=token_detail
                server.save()
            print(token_detail)
            children,count = self.get_folder_children(id, token_detail['access_token'])
            return Response(data={'children': children, 'parent': id,'file_count':count}, status=200)
        except Exception as e:
            return Response(data={'message': str(e)}, status=400)