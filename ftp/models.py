from django.db import models
from files.models import NewUser
from content.models import Folder
from django.core.exceptions import ValidationError
# Create your models here.
class Server_Connection(models.Model):
    TYPE_CHOICES = [
        ('googledrive', 'googledrive'),
        ('onedrive', 'onedrive'),
    ]
    type = models.CharField(max_length=14, choices=TYPE_CHOICES,default='onedrive')
    user=models.ForeignKey(NewUser,related_name='servers',on_delete=models.CASCADE)
    server_name=models.CharField(max_length=30,unique=True)
    user_token=models.JSONField(null=True,blank=True)
    user_email=models.EmailField(blank=True,null=True)


class Sync_Direction(models.Model):
    folder_from_id=models.CharField(max_length=1000)
    folder_to_id=models.ForeignKey(Folder,on_delete=models.CASCADE,related_name='folder_syncs')
    connection=models.ForeignKey(Server_Connection,on_delete=models.CASCADE,related_name='connection_syncs')
    status_url=models.URLField(max_length=1000,null=True,blank=True)
    folder_from_name=models.CharField(max_length=50)


    def save(self,*args, **kwargs):
        syn=Sync_Direction.objects.filter(folder_from_id=self.folder_from_id).first()
        if syn and syn.connection.type==self.connection.type:
            raise ValidationError(f"Sync from {self.folder_from_name} already exists")
        super(Sync_Direction, self).save(*args, **kwargs)