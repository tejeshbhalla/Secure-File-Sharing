from content.models import Link_Model



def revoke_access(user,hash):
    name=hash.__class__.__name__
    if 'Files' in name:
        links=Link_Model.objects.filter(owner=user,file_hash__in=[hash])

        links.delete()
    else:
        links=Link_Model.objects.filter(owner=user,folder_hash__in=[hash])
        links.delete()

