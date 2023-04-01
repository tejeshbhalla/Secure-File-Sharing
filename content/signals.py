from requests import request
from content.utils import get_client_ip
from .models import Files_Model,Folder, Internal_Share_Folders,Link_Model,Internal_Share
from files.models import User_logs,NewUser,Notifications
from django.db.models.signals import pre_save,post_delete,post_save,pre_delete
import json
from .sub_utils import revoke_access


def create_logs(user,message):
    log=User_logs()
    message=json.dumps(message)
    log.actions=message
    log.user=user
    log.save()

def add_logs(sender, instance, **kwargs):
    name=instance.__class__.__name__

    if 'Files' in name:
        user=instance.owner
        message=f'{user.username} uploaded a file {instance.file_name} {instance.filesize}'
        create_logs(user,message)
    if 'Folder' in name:
        user=instance.owner
        message=f'{user.username} uploaded/created a folder {instance.folder_size}'
        create_logs(user,message)
    if 'Link' in name:
        user=instance.owner
        message=f'{user.username} created a link {instance.name}'
        create_logs(user,message)
    if 'Internal' in name:
        user=instance.owner
        
        message=f'{user.username} shared files with  '
        d={"message":message}
        create_logs(user,json.dumps(d))


def add_logs_delete(sender, instance, **kwargs):
    try:
        name=instance.__class__.__name__
        if 'Files' in name:
            user=instance.owner
            message=f'{user}  deleted a file'
            create_logs(user,message)
        if 'Folder' in name:
            user=instance.owner
            message=f'{user} deleted a folder'
            create_logs(user,message)
        if 'Link' in name:
            user=instance.owner
            message=f'{user} deleted a link'
            create_logs(user,message)
    except Exception as e:
            pass

def changed_internal(sender,instance,**kwargs):
    name=instance.__class__.__name__
    try:
            if 'Folders' in name:
                revoke_access(instance.shared_with,instance.folder_hash)
            else:
                revoke_access(instance.shared_with,instance.file_hash)

    except Exception as e:
        pass
def remove_shared_link(sender,instance,**kwargs):
    name=instance.__class__.__name__
    owner=instance.owner
    user=instance.shared_with
    if 'Folder' not in name:
        file=instance.file_hash
        if not instance.can_share_content and owner!=user:
            revoke_access(user,file)
    else:
        
        if not instance.can_share_content and owner!=user:
            folder=instance.folder_hash
            revoke_access(user,folder)
    return 
    
  
post_save.connect(remove_shared_link,sender=Internal_Share)
post_save.connect(remove_shared_link,sender=Internal_Share_Folders)
post_save.connect(add_logs, sender=Files_Model)
post_save.connect(add_logs,sender=Folder)
post_save.connect(add_logs,sender=Link_Model)
post_save.connect(add_logs,sender=Internal_Share)
pre_delete.connect(changed_internal,sender=Internal_Share)
pre_delete.connect(changed_internal,sender=Internal_Share_Folders)
post_delete.connect(add_logs_delete, sender=Files_Model)
post_delete.connect(add_logs_delete,sender=Folder)
post_delete.connect(add_logs_delete,sender=Link_Model)
