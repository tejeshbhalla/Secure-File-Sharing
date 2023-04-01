from content.models import Folder
from rest_framework import serializers
from .models import Server_Connection,Sync_Direction
from files.models import NewUser
import requests
import json

class SyncDirectionSerializer(serializers.ModelSerializer):
    folder_from_name=serializers.SerializerMethodField()
    folder_to_id=serializers.SerializerMethodField()
    class Meta:
        model=Sync_Direction
        fields=['folder_from_id','folder_to_id','folder_from_name']
    
    def get_folder_from_name(self,obj):
        return obj.folder_from_name
    def get_folder_to_id(self,obj):
        return obj.folder_to_id.name

class ServerSerializer(serializers.ModelSerializer):
    syncs=serializers.SerializerMethodField()
    class Meta:
        model=Server_Connection
        fields=['id','server_name','syncs']
        read_only_fields=['id']
    def get_syncs(self,obj):
        all_conn=obj.connection_syncs.all()
        sz=SyncDirectionSerializer(all_conn,many=True)
        return sz.data


    def save(self,validated_data,user):
        server_name=validated_data['server_name']
        obj=Server_Connection(server_name=server_name,user=user)
        obj.save()
        return obj 


class SyncDirectionSerializer2(serializers.ModelSerializer):

    class Meta:
        model=Sync_Direction
        fields=['folder_from_name','folder_to_id','connection','folder_from_id']

    def to_internal_value(self,data):
        if 'connection' in data:
            data['connection']=Server_Connection.objects.get(server_name=data['connection']).id
        if 'folder_to_id' in data:
            if 'folder_to_id'=='root':
                data['folder_to_id']=None
            else:
                data['folder_to_id']=Folder.objects.get(urlhash=data['folder_to_id']).id
        return super(SyncDirectionSerializer2,self).to_internal_value(data)