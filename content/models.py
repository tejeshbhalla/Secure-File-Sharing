from django.db import models
from files.models import NewUser
from content.utils import check_permissions, delete_keys, id_generator,upload_path,delete_folder
import datetime
from django.core.exceptions import ValidationError
from files.utils import file_size
from django_clamav.validators import validate_file_infection
from django.utils import timezone
import os
from storages.backends.azure_storage import AzureStorage
from Varency.settings import AZURE_ACCOUNT_NAME,AZURE_ACCOUNT_KEY
# Create your models here.


#files_app
class Folder(models.Model):
    name=models.CharField(max_length=500)
    size=models.IntegerField(default=0)
    parent=models.ForeignKey('self',related_name='children',on_delete=models.CASCADE,blank=True,null=True,)
    owner=models.ForeignKey(NewUser,related_name='user_folders',on_delete=models.CASCADE,null=True,blank=True)
    date_created=models.DateTimeField(auto_now_add=True)
    shared_with=models.ManyToManyField(NewUser,related_name='shared_folders',blank=True)
    urlhash=models.CharField(max_length=6,null=True,blank=True,unique=True)
    date_modified=models.DateTimeField(default=timezone.now())
    deleted=models.BooleanField(default=False)
    last_deleted=models.DateTimeField(null=True,blank=True)
    def __str__(self):
        return f'{self.name}'

    def order_parent(self):
        if self.parent is None:
            return ['root',self.name]
        order_parent=self.parent.order_parent()
        order_parent.append(self.name)
        return order_parent

    def order_parent_urlhash(self):
        if self.parent is None:
            return ['root',self.urlhash]
        order_parent=self.parent.order_parent_urlhash()
        order_parent.append(self.urlhash)
        return order_parent

    def give_string_path(self):
        path=self.order_parent()
        path_str=self.owner.username+"/"
        for i in path:
            path_str+=i+'/'
        return path_str

    def delete(self, *args, **kwargs):
  
        delete_folder(self)
        super(Folder, self).delete(args, kwargs)


    @property
    def folder_size(self,*args,**kwargs):
        x=0
        for files in self.files.all():
            x+=files.content.size
        y = 512000
        if x< y:
            value = round(x / 1024, 2)
            ext = ' KB'
        elif x < y * 1024:
            value = round(x / (1024 * 1024), 2)
            ext = ' MB'
        else:
            value = round(x / (1024 * 1024 * 1024), 2)
            ext = ' GB'
        return str(value) + ext
        


    def save(self,*args, **kwargs):
        if not self.urlhash:
            self.urlhash = id_generator()
            while Folder.objects.filter(urlhash=self.urlhash).exists():
                 self.urlhash = id_generator()
        super(Folder, self).save()

    def get_subfolders_and_files(self):
        subfolders = []
        files = []
        
        subfolders.extend(self.children.all())
        files.extend(self.files.all())

        for subfolder in self.children.all():
            subfolders_recursive, files_recursive = subfolder.get_subfolders_and_files()
            subfolders.extend(subfolders_recursive)
            files.extend(files_recursive)

        return subfolders, files







class Files_Model(models.Model):
    file_name=models.CharField(max_length=500)
    owner=models.ForeignKey(NewUser,related_name="files",on_delete=models.CASCADE,null=True,blank=True)
    date_uploaded=models.DateTimeField(auto_now_add=True)
    folder=models.ForeignKey(Folder,related_name='files',on_delete=models.CASCADE,blank=True,null=True)
    content=models.FileField(upload_to=upload_path,validators=[validate_file_infection],max_length=1000)
    urlhash=models.CharField(max_length=6,null=True,blank=True,unique=True)
    shared_with=models.ManyToManyField(NewUser,related_name='shared_files',blank=True)
    deleted=models.BooleanField(default=False)
    last_deleted=models.DateTimeField(null=True,blank=True)
    file_size=models.FloatField(default=0)
    uploadinfo=models.JSONField(null=True,blank=True)

    def save(self,*args, **kwargs):
        if not self.urlhash:
            self.urlhash = id_generator()
            while Files_Model.objects.filter(urlhash=self.urlhash).exists() and Folder.objects.filter(urlhash=self.urlhash).exists:
                 self.urlhash = id_generator()
        if self.content:
            gb=self.filesize_gb
            owner=self.owner
            total_space_utilised=owner.storage_amount_used
            total_available_space=owner.total_available_space()
            
            if total_space_utilised+gb>total_available_space:
                raise ValidationError('Space not available kindly upgrade or delete some files')
            else:
                self.file_size+=gb
                owner.storage_amount_used+=gb
                owner.save()
                
        super(Files_Model, self).save()

    def delete(self, *args, **kwargs):
        owner=self.owner
        gb=self.file_size
        
        owner.storage_amount_used-=gb
        owner.save()
        delete_keys(self)
        self.content.delete(save=False)
        super(Files_Model, self).delete(args, kwargs)


    def clean(self):
        tenant=self.owner.tenant
        can_upload_file=file_size(tenant,self)
        if not can_upload_file:
            raise ValidationError('Kindly upload files below the limits')
        
    

    def __str__(self):
        return f'{self.file_name}_{self.owner}'
    @property
    def filesize(self):
        x = self.content.size
        y = 512000
        if x < y:
            value = round(x / 1024, 2)
            ext = ' KB'
        elif x < y * 1024:
            value = round(x / (1024 * 1024), 2)
            ext = ' MB'
        else:
            value = round(x / (1024 * 1024 * 1024), 2)
            ext = ' GB'
        return str(value) + ext

    @property
    def filesize_gb(self):
        x=self.content.size
        value = round(x / (1024 * 1024 * 1024), 10)
        return float(value)
        
    def resave(self,*args,**kwargs):
        if self.urlhash:
            super(Files_Model,self).save()

    def path(self,*args,**kwargs):
        if self.folder==None:
            return f'{self.owner.username}/{self.urlhash}/{self.file_name}'
        else:
            path=os.path.join(self.folder.order_parent_urlhash()[1:])
            return path/{self.file_name}
        pass
    def order_path(self,*args,**kwargs):
        if self.folder==None:
            return f'{self.owner.username}/{self.file_name}'
        else:
            path_='/'.join(self.folder.order_parent()[1:])
 
            return path_+'/'+self.file_name
        pass






class Link_Model(models.Model):
    Access_Choice = (("employee","Employee"),
                    ("client","Client"))
    name=models.CharField(max_length=30)
    shared_with=models.ManyToManyField(NewUser,related_name='shared_link')
    owner=models.ForeignKey(NewUser,related_name='shared_links',on_delete=models.CASCADE,null=True,blank=True)
    access_type=models.CharField(max_length=20,choices=Access_Choice,default='Employee')
    link_hash=models.CharField(max_length=6,unique=True)
    file_hash=models.ManyToManyField(Files_Model,related_name='link_files')
    folder_hash=models.ManyToManyField(Folder,related_name='link_folders')
    expiry_date=models.DateTimeField(null=True)
    is_downloadable=models.BooleanField(default=False)
    password=models.CharField(max_length=100,null=True)
    generated_on=models.DateTimeField(auto_now_add=True)
    access_limit=models.IntegerField(null=True)
    link_type=models.CharField(max_length=100)
    is_proctored=models.BooleanField(default=False)
    is_approved=models.BooleanField(default=False)
    prevent_forwarding=models.BooleanField(default=False)
    deleted=models.BooleanField(default=False)
    is_favourite=models.BooleanField(default=True)
    is_drm=models.BooleanField(default=False)

    def validate_permissions(self):
        permissions=check_permissions(self)
        can_add_date_to_link=permissions['can_add_date_to_link']
        can_access_limit=permissions['can_access_limit']
        has_proctored_link=permissions['has_proctored_link']
        has_email_forwading=permissions['has_email_forwading']
        has_link_password=permissions['has_link_password']
        if self.is_proctored and not has_proctored_link:
            return ValidationError('Proctor cannot be added (Not in plan)')
        if self.expiry_date and not can_add_date_to_link:
            return ValidationError('Date-time cannot be added (Not in plan)')
        if self.access_limit and not can_access_limit:
            return ValidationError('Access limit cannot be added (Not in plan)')
        if self.prevent_forwarding and not has_email_forwading:
            return ValidationError('Email forwarding cannot be added (Not in plan)')
        if self.password and not has_link_password:
            return ValidationError('Password cannot be added (Not in plan)')
        return
    
    @staticmethod
    def search_parent_file(link_hash,file):
        folder=file.folder
        while folder:
            link=Link_Model.objects.filter(link_hash=link_hash,folder_hash__in=[folder]).first()
            if link:
                return link
            else:
                folder=folder.parent
        return None
    @staticmethod
    def search_parent(link_hash,folder):
        folder=folder.parent
        while folder:
            link=Link_Model.objects.filter(link_hash=link_hash,folder_hash__in=[folder]).first()
            if link:
                return link
            else:
                folder=folder.parent
        return None
        

    def save(self,*args, **kwargs):
        self.validate_permissions()
        if not self.link_hash:
            self.link_hash=id_generator()
            while Link_Model.objects.filter(link_hash=self.link_hash).exists():
                self.link_hash=id_generator()
        super(Link_Model, self).save(*args, **kwargs)

    @staticmethod
    def genereate_password():
        password=id_generator(size=8)
        return password
    


    

    def __str__(self):
        return f'{self.link_hash}_{self.owner}'




class Internal_Share(models.Model):
    owner=models.ForeignKey(NewUser,related_name='internal_group',on_delete=models.CASCADE,null=True,blank=True)
    shared_with=models.ForeignKey(NewUser,related_name='files_shared_with_you',on_delete=models.CASCADE,null=True,blank=True)
    link_hash=models.CharField(max_length=6,unique=True)
    file_hash=models.ForeignKey(Files_Model,related_name='internal_link_files',on_delete=models.CASCADE,null=True,blank=True)
    is_downloadable=models.BooleanField(default=False)
    has_read=models.BooleanField(default=True)
    can_add_delete_content=models.BooleanField(default=False)
    can_share_content=models.BooleanField(default=False)
    can_download_content=models.BooleanField(default=False)
    is_proctored=models.BooleanField(default=False)
    def save(self,*args, **kwargs):
        if not self.link_hash:
            self.link_hash=id_generator()
            while Internal_Share.objects.filter(link_hash=self.link_hash).exists():
                self.link_hash=id_generator()
        super(Internal_Share, self).save(*args, **kwargs)

    def __str__(self):
        return f'{self.link_hash}_{self.owner}'
    


class Internal_Share_Folders(models.Model):
    owner=models.ForeignKey(NewUser,related_name='internal_group_2',on_delete=models.CASCADE,null=True,blank=True)
    shared_with=models.ForeignKey(NewUser,related_name='folders_shared_with_you',on_delete=models.CASCADE,null=True,blank=True)
    link_hash=models.CharField(max_length=6,unique=True)
    folder_hash=models.ForeignKey(Folder,related_name='internal_link_folders',on_delete=models.CASCADE,null=True,blank=True)
    is_downloadable=models.BooleanField(default=False)
    has_read=models.BooleanField(default=True)
    can_add_delete_content=models.BooleanField(default=False)
    can_share_content=models.BooleanField(default=False)
    can_download_content=models.BooleanField(default=False)
    is_proctored=models.BooleanField(default=False)
    def save(self,*args, **kwargs):
        if not self.link_hash:
            self.link_hash=id_generator()
            while Internal_Share_Folders.objects.filter(link_hash=self.link_hash).exists():
                self.link_hash=id_generator()
        super(Internal_Share_Folders, self).save(*args, **kwargs)

    def __str__(self):
        return f'{self.link_hash}_{self.owner}'
    def delete(self, *args, **kwargs):
        super(Internal_Share_Folders, self).delete(args, kwargs)

    @staticmethod
    def search_parent(user,sub_folder):
        folder=sub_folder
        while folder:
            share=Internal_Share_Folders.objects.filter(shared_with=user,folder_hash=folder).first()
    
            if share:
                return share
            else:
                folder=folder.parent
        return None
    @staticmethod
    def search_parent_file(user,file):
        folder=file.folder
        while folder:
            share=Internal_Share_Folders.objects.filter(shared_with=user,folder_hash=folder).first()
            if share:
                return share
            else:
                folder=folder.parent
        return None






#logs model
class Link_logs(models.Model):
    actions=models.JSONField()
    link=models.ForeignKey(Link_Model,related_name='logs',on_delete=models.SET_NULL,null=True)
    owner=models.ForeignKey(NewUser,related_name='link_logs',on_delete=models.CASCADE,null=True,blank=True)







class Request_File(models.Model):
    file_name=models.CharField(max_length=100)
    user_from=models.ForeignKey(NewUser,related_name='requests',on_delete=models.CASCADE)
    user_to=models.ForeignKey(NewUser,on_delete=models.CASCADE,related_name='requests_recieved')
    request_hash=models.CharField(max_length=6,unique=True)

    def save(self,*args, **kwargs):
        if not self.request_hash:
            self.request_hash=id_generator()
            while Request_File.objects.filter(request_hash=self.request_hash).exists():
                self.request_hash=id_generator()
        super(Request_File, self).save(*args, **kwargs)


