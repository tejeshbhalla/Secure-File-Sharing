from files.utils import id_generator_2
from rest_framework import serializers
from .models import Admin,Employee, Group_Permissions,NewUser, Notifications,People_Groups, Tenant, User_logs
import datetime
from django.utils import timezone


class RegisterUser(serializers.ModelSerializer):
    password=serializers.CharField(max_length=68,min_length=6,write_only=True)
    phone_number=serializers.CharField(max_length=20,write_only=True)
    class Meta:
        model=NewUser
        fields=['name','email','username','password','phone_number']

    def save(self,validated_data,tenant):
        email = validated_data['email']
        username = validated_data['username']
        password = validated_data['password']
        name=validated_data['name']
        phone_number=validated_data['phone_number']
        if validated_data.get('is_admin') or len(tenant.members.all())==0:
            
            user=Admin(email=email,username=username,name=name,phone_number=phone_number,tenant=tenant,is_tenant_owner=True)
            user.set_password(password)
            user.save()
        else:
            user=Employee(email=email,username=username,name=name,phone_number=phone_number,tenant=tenant)
            user.set_password(password)
            user.save()
        return user 


class TenantSerializer(serializers.ModelSerializer):
    class Meta:
        model=Tenant
        fields=['name','subdomain']

    def save(self,validated_data):
        name=validated_data['name']
        subdomain=validated_data['subdomain']
        t=Tenant(name=name,subdomain=subdomain,paid_until=timezone.now())
        t.save()
        return t 



class CreateGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model=People_Groups
        fields=['owner','name','description']

    def create(self,validated_data):
        grp=People_Groups(**validated_data)
        grp.save()
        permission=Group_Permissions(group=grp,user=validated_data['owner'],is_admin=True,has_read=True,can_add_delete_content=True)
        permission.save()
        return grp

    def update(self,validated_data):
        grp=validated_data['group']
        grp.name=validated_data['name']
        grp.description=validated_data['description']
        grp.save()
        return grp
    def to_internal_value(self,data):
        if 'owner' in data:
            data['owner']=data['owner'].id
        return super(CreateGroupSerializer,self).to_internal_value(data)
    
    



class DetailGroupSerializer(serializers.ModelSerializer):
    urlhash=serializers.SerializerMethodField()
    members=serializers.SerializerMethodField()
    class Meta:
        model = People_Groups
        fields =["name","urlhash",'description','members']    
    def get_urlhash(self,obj):
        return obj.group_hash
    def get_members(self,obj):
        all_members_per=Group_Permissions.objects.filter(group=obj)
        all_members=[]
        for i in all_members_per:
            is_owner_user=obj.owner==i.user
            all_members.append({'username':i.user.username,'is_admin':i.is_admin,'can_share_content':i.can_share_content,'is_proctored':i.is_proctored,'can_download_content':i.can_download_content,'has_read':i.has_read,'can_add_delete_content':i.can_add_delete_content,'email':i.user.email,'is_owner':is_owner_user})
        return all_members


class UserSerializer(serializers.ModelSerializer):

    class Meta:
        model=NewUser
        fields=['name','email','username','is_admin','is_active','date']



class WorkSerializer(serializers.Serializer):
    csv_file = serializers.FileField()

    def create(self, validated_data,tenant,*args, **kwargs):
     csv_input = validated_data.pop("csv_file", None)
     if csv_input: 
          users=[]
          passwords=[]
          csv_reader=bytes.decode(csv_input.read())
          print(csv_reader)
          for i in csv_reader.split()[1:]:
              name,username,email,is_admin=i.split(',')
              if is_admin=='FALSE':
                  is_admin=False
              elif is_admin=='TRUE':
                  is_admin=True
              password=id_generator_2(10)

              user=NewUser(name=name,username=username,email=email,is_admin=is_admin,tenant=tenant)
              user.set_password(password)
              users.append(user)
              passwords.append(password)
          NewUser.objects.bulk_create(users)

     return users,passwords

class Logs_Serializer(serializers.ModelSerializer):
    user=RegisterUser()
    class Meta:
        model=User_logs
        fields=["actions","datetime",'user']


class Notification_Serializer(serializers.ModelSerializer):
     class Meta:
         model=Notifications
         fields=['text','user','read','date','type']



class SupportRequestSerializer(serializers.Serializer):
    message = serializers.CharField()
    additional_thoughts = serializers.CharField(required=False)
    file = serializers.FileField(required=False)