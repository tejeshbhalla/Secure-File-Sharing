from .models import Folder,Internal_Share,Internal_Share_Folders
from django.core.exceptions import ValidationError



def validate_double_share(obj,user):
    name=obj.__class__.__name__
    if 'Folder' in name:
        folder=Internal_Share_Folders.objects.filter(folder_hash=obj,shared_with=user).first()
        if folder:
            raise ValidationError(f'Folder share already exists with user {user.username}')
    if 'Files' in name:
        file=Internal_Share.objects.filter(file_hash=obj,shared_with=user).first()
        if file:
            raise ValidationError(f'File share already exists with user {user.username}')



def validate_share_already_exist(obj,user,owner):
    name=obj.__class__.__name__
    if 'Folder' in name:
        validate_double_share(obj,user)
        folder=Internal_Share_Folders.objects.filter(folder_hash=obj,shared_with=user,owner=owner).first()
        if folder:
            raise ValidationError(f'Already shared folder with {user.username} kindly update their permissions in case of a change')
        if owner==user:
            raise ValidationError(f'Cant share with yourself')
        if obj.owner==user:
            raise ValidationError(f'Cant share with yourself')
    if 'Files' in name:
        file=Internal_Share.objects.filter(file_hash=obj,shared_with=user,owner=owner).first()
        validate_double_share(obj,user)
        if file:
            raise ValidationError(f'Already shared file with {user.username} kindly update their permissions in case of a change')
        if owner==user:
            raise ValidationError(f'Cant share with yourself')
        if obj.owner==user:
            raise ValidationError(f'Cant share with yourself')

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

