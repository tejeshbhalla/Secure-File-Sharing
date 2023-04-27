from django.db import models
from django.contrib.auth.models import AbstractBaseUser,BaseUserManager,PermissionsMixin
from django.forms import ValidationError
from Varency.settings import SECRET_KEY
import jwt 
from datetime import date, datetime,timedelta
from Varency import settings
from files.utils import id_generator_2
from django.contrib.postgres.fields import ArrayField
from django.core.validators import MaxValueValidator





# Create your models here.(

class  Plan(models.Model):
    name=models.CharField(max_length=10)
    description=models.CharField(max_length=100)

    class Meta:
        abstract=True

class Basic_Plan(Plan):
    no_of_users=models.IntegerField(default=2,validators=[MaxValueValidator(2)])
    max_storage=models.IntegerField(default=5,validators=[MaxValueValidator(5)])
    max_upload_file_size=models.IntegerField(default=2,validators=[MaxValueValidator(2)])
    max_recovery_days=models.IntegerField(default=3,validators=[MaxValueValidator(3)])
    can_link_log=models.BooleanField(default=True)
    can_add_date_to_link=models.BooleanField(default=True)
    can_access_limit=models.BooleanField(default=True)
    can_data_backup=models.BooleanField(default=False)
    can_watermark_pii=models.BooleanField(default=False)
    has_file_versioning=models.BooleanField(default=False)
    has_proctored_link=models.BooleanField(default=False)
    has_email_forwarding=models.BooleanField(default=False)
    has_admin_panel=models.BooleanField(default=False)
    hot_linking_prevention=models.BooleanField(default=True)
    has_groups=models.BooleanField(default=False)
    has_link_password=models.BooleanField(default=True)
    drm_limit_per_user=models.IntegerField(default=1,validators=[MaxValueValidator(1)])


class Premium_Plan(Plan):
    no_of_users=models.IntegerField(default=10,validators=[MaxValueValidator(10)])
    max_storage=models.IntegerField(default=1000,validators=[MaxValueValidator(1000)])
    max_upload_file_size=models.IntegerField(default=100,validators=[MaxValueValidator(100)])
    max_recovery_days=models.IntegerField(default=7,validators=[MaxValueValidator(7)])
    can_link_log=models.BooleanField(default=True)
    can_add_date_to_link=models.BooleanField(default=True)
    can_access_limit=models.BooleanField(default=True)
    can_data_backup=models.BooleanField(default=True)
    can_watermark_pii=models.BooleanField(default=True)
    has_file_versioning=models.BooleanField(default=True)
    has_proctored_link=models.BooleanField(default=True)
    has_email_forwarding=models.BooleanField(default=True)
    has_admin_panel=models.BooleanField(default=True)
    hot_linking_prevention=models.BooleanField(default=True)
    has_groups=models.BooleanField(default=True)
    has_link_password=models.BooleanField(default=True)
    drm_limit_per_user=models.IntegerField(default=3,validators=[MaxValueValidator(3)])

    




class Tenant(models.Model):
    name=models.CharField(max_length=100)
    subdomain=models.CharField(max_length=100,unique=True)
    plan_type=models.CharField(max_length=100,choices=(('Basic','Basic'),('Premium','Premium')),default='Basic')
    basic_plan=models.ForeignKey(Basic_Plan,on_delete=models.CASCADE,related_name='tenants',null=True,default=1)
    premium_plan=models.ForeignKey(Premium_Plan,on_delete=models.CASCADE,related_name='tenants',null=True)
    on_trial=models.BooleanField(default=False)
    paid_until=models.DateTimeField()
    created_at=models.DateTimeField(auto_now_add=True)

    @property
    def no_of_users(self):
        return len(self.members.all())

    def __str__(self):
        return self.subdomain


class NewUserManager(BaseUserManager):
    def create_superuser(self,username,email,password=None,**kwargs):
        kwargs.setdefault('is_superuser',True)
        kwargs.setdefault('is_admin',True)
        kwargs.setdefault('is_active',True)
        kwargs.setdefault('is_staff',True)
        if username is None:
            return ValidationError("username is required")
        if email is None:
            return ValidationError("email is required")

        return self.create_user(username,email,password,**kwargs)

    def create_user(self,username,email,password,**kwargs):
        if username is None:
            return ValidationError("username is required")
        if email is None:
            return ValidationError("email is required")
        user=self.model(email=self.normalize_email(email),username=username,**kwargs)
        user.set_password(password)
        user.save()
       

        return user 



class NewUser(AbstractBaseUser,PermissionsMixin):
    name=models.CharField(max_length=50)
    email=models.EmailField(unique=True)
    username=models.CharField(max_length=50,unique=True)
    is_admin=models.BooleanField(default=False)
    is_active=models.BooleanField(default=True)
    is_staff=models.BooleanField(default=False)
    is_activated=models.BooleanField(default=False)
    date=models.DateTimeField(auto_now_add=True)
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS=['username']
    objects=NewUserManager()
    two_factor_activated=models.BooleanField(default=False)
    token_value=models.CharField(max_length=800,null=True,blank=True)
    last_access=models.DateTimeField(auto_now_add=True,null=True,blank=True)
    phone_number=models.CharField(max_length=20,unique=True,null=True,blank=True)    
    is_tenant_owner=models.BooleanField(default=False)
    tenant=models.ForeignKey(Tenant,on_delete=models.CASCADE,related_name='members',null=True,blank=True)
    storage_amount_used=models.FloatField(default=0)
    class Types(models.TextChoices):
        ADMIN = "ADMIN", "Admin"
        EMPLOYEE = "EMPLOYEE", "Employee"

    type=models.CharField(("_Type"),max_length=50,choices=Types.choices,default=Types.EMPLOYEE)


    def token(self,setting):
        if setting=='login':
            if self.token_value==None:
                delta=timedelta(hours=24)
                token=jwt.encode({'username':self.username,'email':self.email,'exp':datetime.utcnow()+delta},SECRET_KEY,algorithm='HS256')
                self.token_value=token
                self.save()
            token_bt=BlacklistedToken.objects.filter(token=self.token_value).first()
            if not token_bt:
                try:
                    payload=jwt.decode(self.token_value,settings.SECRET_KEY,algorithms=['HS256',])
                    time_left=payload.get('exp')
                    time_left=datetime.fromtimestamp(time_left)
                    if time_left>datetime.now():
                        token=self.token_value
                    else:
                        delta=timedelta(hours=24)
                        token=jwt.encode({'username':self.username,'email':self.email,'exp':datetime.utcnow()+delta},SECRET_KEY,algorithm='HS256')
                        self.token_value=token
                        self.save()
                except Exception as e:
                    if 'expired' in str(e):
                        delta=timedelta(hours=24)
                        token=jwt.encode({'username':self.username,'email':self.email,'exp':datetime.utcnow()+delta},SECRET_KEY,algorithm='HS256')
                        self.token_value=token
                        self.save()

            elif token_bt:
                delta=timedelta(hours=24)
                token=jwt.encode({'username':self.username,'email':self.email,'exp':datetime.utcnow()+delta},SECRET_KEY,algorithm='HS256')
                self.token_value=token
                self.save()

        if setting=='reset_password':
            delta=timedelta(minutes=5)
            token=jwt.encode({'id':self.id,'exp':datetime.utcnow()+delta,'aim':"reset_password"},SECRET_KEY,algorithm='HS256')
        if setting=='activate':
            delta=timedelta(minutes=10)
            token=jwt.encode({'id':self.id,'exp':datetime.utcnow()+delta,'aim':'activate'},SECRET_KEY,algorithm='HS256')
        return token
    def delete(self, *args, **kwargs):
        self.user_folders.all().delete()
        self.files.all().delete()
        super(NewUser, self).delete(args, kwargs)

    def total_available_space(self):
        tenant=self.tenant
        plan_type=self.tenant.plan_type
        if plan_type=='Basic':
            return tenant.basic_plan.max_storage
        elif plan_type=='Premium':
            return tenant.premium_plan.max_storage/tenant.premium_plan.no_of_users
        return 0
    def __str__(self):
        return f'{self.username}'





    

class BlacklistedToken(models.Model):
    token=models.CharField(max_length=800,unique=True)
    time_expired=models.DateTimeField()
    user=models.ForeignKey(NewUser, null=True, blank=True,related_name='black_listed',on_delete=models.CASCADE)


class Otp_Token(models.Model):
    otp=models.CharField(max_length=6,unique=True)
    time_expired=models.DateTimeField()
    user=models.ForeignKey(NewUser,null=True,blank=True,related_name='otps',on_delete=models.CASCADE)



class People_Groups(models.Model):
    name=models.CharField(max_length=100)
    group_hash=models.CharField(max_length=6,unique=True)
    files=models.ManyToManyField('content.Files_Model',related_name='group_files')
    folders=models.ManyToManyField('content.Folder',related_name='group_folders')
    owner=models.ForeignKey(NewUser,on_delete=models.CASCADE,related_name='owned_groups')
    description=models.TextField(max_length=200)
    created=models.DateTimeField(auto_now_add=True)
    def save(self,*args, **kwargs):
        if not self.group_hash:
            self.group_hash=id_generator_2()
            while People_Groups.objects.filter(group_hash=self.group_hash).exists():
               self.group_hash=id_generator_2()
        super(People_Groups, self).save(*args, **kwargs)

    def __str__(self):
        return f'{self.name}'
    
    @staticmethod
    def search_parent_file(group_hash,file):
        if not file:
            return None
        folder=file.folder
        while folder:
            group=People_Groups.objects.filter(group_hash=group_hash,files__in=[file])
            if group:
                return group
            else:
                folder=folder.parent
        return None
    
    @staticmethod
    def search_parent(group_hash,folder):
        folder=folder.parent
        while folder:
            group=People_Groups.objects.filter(group_hash=group_hash,folders__in=[folder]).first()
            if group:
                return group
            else:
                folder=folder.parent
        return None
    

class Group_Permissions(models.Model):
    group=models.ForeignKey(People_Groups,related_name='group_permissions',on_delete=models.CASCADE)
    user=models.ForeignKey(NewUser,related_name='members',on_delete=models.CASCADE)
    is_admin=models.BooleanField(default=False)
    has_read=models.BooleanField(default=True)
    can_add_delete_content=models.BooleanField(default=False)
    can_share_content=models.BooleanField(default=False)
    can_download_content=models.BooleanField(default=False)
    is_proctored=models.BooleanField(default=False)
    is_favourite=models.BooleanField(default=False)






class AdminManager(models.Manager):
    def get_queryset(self, *args, **kwargs):
        return super().get_queryset(*args, **kwargs).filter(type=NewUser.Types.ADMIN)






class EmployeeManager(models.Manager):
    def get_queryset(self, *args, **kwargs):
        return super().get_queryset(*args, **kwargs).filter(type=NewUser.Types.EMPLOYEE)

    


class Admin(NewUser):
    objects = AdminManager()
    class Meta:
        proxy=True

class Employee(NewUser):
    objects = EmployeeManager()
    class Meta:
        proxy=True


class User_logs(models.Model):
    actions=models.JSONField()
    user=models.ForeignKey(NewUser,related_name='user_logs',on_delete=models.CASCADE,null=True,blank=True)
    datetime=models.DateTimeField(default=datetime.now())

class Notifications(models.Model):
    text=models.JSONField()
    user=models.ForeignKey(NewUser,related_name='user_notifications',on_delete=models.CASCADE,null=True,blank=True)
    read=models.BooleanField(default=False)
    date=models.DateTimeField(auto_now_add=True)
    type=models.CharField(max_length=100,default=None)



class Group_logs(models.Model):
    actions=models.JSONField()
    group=models.ForeignKey(People_Groups,related_name='group_logs',on_delete=models.CASCADE,null=True,blank=True)
    datetime=models.DateTimeField(default=datetime.now())

