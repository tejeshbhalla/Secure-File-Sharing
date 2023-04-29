from .models import Folder,Internal_Share,Internal_Share_Folders
from django.core.exceptions import ValidationError



def check_parent(parents,folder_hash):
    for i in parents:
        obj=Folder.objects.filter(urlhash=folder_hash).first()
        parent=i
        if parent.parent==None:
            if parent==obj:
                return True
        while parent!=None:
           
            if parent.parent==obj.parent:
                return True
            obj=obj.parent
    return False

def validate_share_already_exist(obj,user,owner):
    folder=Internal_Share_Folders.objects.filter(folder_hash=obj,shared_with=user,owner=owner).first()
    if folder:
        raise ValidationError(f'Already shared folder with {user.username} kindly update their permissions in case of a change')
    file=Internal_Share.objects.filter(file_hash=obj,shared_with=user,owner=owner).first()
    if file:
        raise ValidationError(f'Already shared file with {user.username} kindly update their permissions in case of a change')