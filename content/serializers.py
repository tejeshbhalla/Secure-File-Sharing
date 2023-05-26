import email
from email.policy import default
from pyexpat import model

from content.utils import create_notifications

from .models import Folder,Files_Model, Internal_Share, Internal_Share_Folders,Link_Model, Request_File
from files.models import NewUser
from rest_framework import serializers
import jwt
from files.models import NewUser
from annoying.functions import get_object_or_None
from rest_framework.response import Response
from rest_framework import status
from django.forms import ValidationError
from files.serializers import RegisterUser
from Varency.settings import FRONT_END_URL

class FolderSerializer(serializers.ModelSerializer):
    parent=serializers.CharField(min_length=6,allow_blank=True)
    shared_with=serializers.ListField(child=serializers.CharField(min_length=4,allow_blank=True))
    class Meta:
        model = Folder
        fields = ['name','parent','shared_with']

    def create(self, validated_data,tenant):
        if 'parent' in validated_data:
            if len(validated_data['parent'])==6:
                validated_data['parent'] = get_object_or_None(Folder,urlhash=validated_data['parent'])
                if validated_data['parent'].owner!=validated_data['owner']:
                    per=Internal_Share_Folders.objects.get(shared_with=validated_data['owner'],folder_hash=validated_data['parent'])
                    if  per.can_add_delete_content:
                        validated_data['owner']=per.owner
                    else:
                        raise ValidationError(f'Dont have privelages')
            else:
                validated_data['parent'] =None
        shared_with=[]
        if 'shared_with' in validated_data:
            for email in validated_data['shared_with']:
                obj=get_object_or_None(NewUser,email=email,tenant=tenant)
                if obj==None:
                    raise ValidationError(f"{email} does not exist")
                shared_with.append(obj.id)

        validated_data.pop('shared_with')
        obj=Folder(**validated_data)
        obj.save()
        obj.shared_with.add(*shared_with)

        obj.save()
        return obj

    def update(self,validated_data,urlhash,tenant):
        folder=get_object_or_None(Folder,urlhash=urlhash)
        if folder==None:
            return None
        if 'name' in validated_data:
            name=validated_data['name']
            folder.name=name
        shared_with=[]
        if 'shared_with' in validated_data:
            for email in validated_data['shared_with']:
                obj=get_object_or_None(NewUser,email=email,tenant=tenant)
                if obj==None:
                    raise ValidationError(f"{email} does not exist")
                shared_with.append(obj.id)
            folder.shared_with.set(shared_with)
        if 'parent' in validated_data:
            folder_parent=Folder.objects.filter(urlhash=validated_data['parent'])
            if len(folder_parent)==0:
                return None
            folder.parent=folder_parent[0]
        folder.save()
        return folder

class FileSerializer(serializers.ModelSerializer):
    
    class Meta:
        model=Files_Model
        fields = ['file_name','content']

class DetailFileSerializer(serializers.ModelSerializer):
    owner=RegisterUser()
    is_file=serializers.SerializerMethodField()
    name=serializers.SerializerMethodField()
    date_created=serializers.SerializerMethodField()
    class Meta:
        model=Files_Model
        fields = ['name','content','urlhash','is_file','owner','date_created']
    def get_is_file(self,obj):
        return True
    def get_name(self,obj):
        return obj.file_name
    def get_date_created(self,obj):
        return obj.date_uploaded


class DetailFolderSerializer(serializers.ModelSerializer):
    owner=RegisterUser()
    shared_with=RegisterUser(many=True)
    path=serializers.SerializerMethodField()
    hash_path=serializers.SerializerMethodField()
    files=FileSerializer(many=True)
    is_folder=serializers.SerializerMethodField()
    class Meta:
        model = Folder
        fields =['id', 'name', 'parent','shared_with','owner','path','files','hash_path','urlhash','children','is_folder','date_created'] 
    def get_is_folder(self,obj):
        return True  
    def get_path(self,obj):
        if obj==None:
            return
        return obj.order_parent()
    def get_hash_path(self,obj):
        if obj==None:
            return
        return obj.order_parent_urlhash()





        
class Link_Serializer(serializers.ModelSerializer):
    owner=serializers.CharField(min_length=6,allow_blank=True)
    shared_with=serializers.ListField(child=serializers.CharField(min_length=4))
    file_hash=serializers.ListField(child=serializers.CharField(min_length=6))
    is_password=serializers.BooleanField(default=False)
    folder_hash=serializers.ListField(child=serializers.CharField(min_length=6))
    access_limit=serializers.IntegerField(default=None)
    expiry_date=serializers.DateTimeField(allow_null=True)
    class Meta:
        model=Link_Model
        fields=['name','shared_with','owner','access_type','expiry_date','is_downloadable','file_hash','is_password','folder_hash','access_limit','is_proctored',
        'prevent_forwarding','is_favourite','is_drm']

    def validate_file_hash(self, file_hash):
        for i in file_hash:
            if len(Files_Model.objects.filter(urlhash=i))==0:
                raise serializers.ValidationError(f"File Does Not Exist {file_hash}")

        return file_hash

    def validate_folder_hash(self, folder_hash):
        for i in folder_hash:
            if len(Folder.objects.filter(urlhash=i))==0:
                raise serializers.ValidationError(f"Folder Does Not Exist {i}")

        return folder_hash

    def create(self, validated_data,user,access_type,tenant):
        if 'owner' in validated_data:
            validated_data['owner'] = user

        file_hash=[]
        folder_hash=[]
        if 'file_hash' in validated_data:

            for file_hashes in validated_data['file_hash']:
    
                obj=get_object_or_None(Files_Model,urlhash=file_hashes)
                if obj==None or obj.owner.email!=user.email:
                    internal_share=get_object_or_None(Internal_Share,shared_with=user,file_hash=obj)
                    parent=Internal_Share_Folders.search_parent_file(user,obj)
                    if not internal_share or not internal_share.can_share_content:
                        if not parent or not parent.can_share_content:
                            raise ValidationError("File does not exist or user has no permission to share")
                        else:
                            create_notifications(parent.owner,f'{user.email} created a link of your file {obj.file_name}')
                            file_hash.append(obj.id)
                            validated_data['owner']=obj.owner
                            if validated_data['is_downloadble'] != parent.can_download_content:
                                raise ValidationError('You are only authorized to give permissions that you own')
                            if validated_data['is_proctored'] != parent.is_proctored:
                                raise ValidationError('You are only authorized to give permissions that you own')
                            
                    else:
                        create_notifications(internal_share.owner,f'{user.email} created a link of your file {obj.file_name}')
                        file_hash.append(obj.id)
                        validated_data['owner']=obj.owner
                        if validated_data['is_downloadble'] != internal_share.can_download_content:
                                raise ValidationError('You are only authorized to give permissions that you own')
                        if validated_data['is_proctored'] != internal_share.is_proctored:
                                raise ValidationError('You are only authorized to give permissions that you own')
                file_hash.append(obj.id)
        if 'folder_hash' in validated_data:
            for folder in validated_data['folder_hash']:
                obj=get_object_or_None(Folder,urlhash=folder)
                if obj==None or obj.owner.email!=user.email:
                    internal_share_folder=get_object_or_None(Internal_Share_Folders,shared_with=user,folder_hash=obj)
                    parent=Internal_Share_Folders.search_parent(user,obj)
                    if not internal_share_folder or  not internal_share_folder.can_share_content:
                        if not parent or not parent.can_share_content:
                            raise ValidationError("File does not exist or user has no permission to share")
                        else:
                            create_notifications(parent.owner,f'{user.email} created a link of your folder {obj.name}')
                            folder_hash.append(obj.id)
                            validated_data['owner']=obj.owner
                    else:
                        create_notifications(internal_share_folder.owner,f'{user.email} created a link of your folder {obj.name}')
                        folder_hash.append(obj.id)
                        validated_data['owner']=obj.owner
                folder_hash.append(obj.id)
        shared_with=[]
        if 'shared_with' in validated_data:
            if access_type!='client':
                for email in validated_data['shared_with']:
                    
                    obj=get_object_or_None(NewUser,email=email,tenant=tenant)
                    if obj==None:
                        raise ValidationError("user does not exist")
                    shared_with.append(obj.id)
            


        if validated_data.get('is_password',None):
            
            password_=Link_Model().genereate_password()
            validated_data['password']=password_
        if validated_data.get("access_limit"):
            if validated_data['access_limit']<0:
                validated_data['access_limit']=None
        validated_data.pop('is_password')
        validated_data.pop('shared_with')
        validated_data.pop('file_hash')
        validated_data.pop('folder_hash')
    
        obj=Link_Model(**validated_data)
        obj.save()
        obj.shared_with.add(*shared_with)
        obj.file_hash.add(*file_hash)
        obj.folder_hash.add(*folder_hash)
        obj.save()
        return obj

    def to_internal_value(self,data):
        if 'expiry_date' in data:
            if data['expiry_date']=='':
                data['expiry_date']=None
        return super(Link_Serializer,self).to_internal_value(data)
    


class Detail_Link_Serializer(serializers.ModelSerializer):
    url=serializers.SerializerMethodField()

    def get_url(self,obj):
        return f'https://{obj.owner.tenant.subdomain}.{FRONT_END_URL}view/link_detail/{obj.link_hash}/none'
    class Meta:
        model=Link_Model
        fields='__all__'
        #extra_kwargs = '__all__'


    


class Request_File_Serializer(serializers.ModelSerializer):

    class Meta:
        model=Request_File
        fields=['file_name','user_to','user_from']





     
    


    
