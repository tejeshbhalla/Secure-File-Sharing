from .models import Folder



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