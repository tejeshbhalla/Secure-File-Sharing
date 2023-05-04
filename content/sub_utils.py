from content.models import Link_Model,Files_Model,Folder
from azure.storage.blob import BlobServiceClient, ContainerClient,generate_blob_sas, BlobSasPermissions,BlobClient
from Varency.settings import AZURE_CONNECTION_STRING,AZURE_CONTAINER
from .utils import id_generator
import os

def revoke_access(user,hash):
    name=hash.__class__.__name__
    if 'Files' in name:
        links=Link_Model.objects.filter(owner=user,file_hash__in=[hash])

        links.delete()
    else:
        links=Link_Model.objects.filter(owner=user,folder_hash__in=[hash])
        links.delete()


def id_generator_2():
    id=id_generator()
    while Folder.objects.filter(urlhash=id).exists():
            id = id_generator()
    return id



def copy_files(files_list,target_folder):
    d={}
    if not target_folder:
        path=f'{files_list[0].owner.username}/root'
    else:
        path=target_folder.order_parent_urlhash()
        path=os.path.join(path)
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
    for i in files_list:
        name=i.file_name
        file_path=path+'/'+name
        d[name]=[file_path,i.owner]

        source_blob_client = blob_service_client.get_blob_client(
        container=AZURE_CONTAINER, blob=i.content.name)
        destination_blob_client = blob_service_client.get_blob_client(
        container=AZURE_CONTAINER, blob=file_path)
        destination_blob_client.start_copy_from_url(source_blob_client.url)
    for i in d:
        file=Files_Model(file_name=i,owner=d[i][1],folder=target_folder)
        file.content.name=d[i][0]
        file.save()
    return 

    
def copy_folder_with_contents(folder, destination_folder):
    """
    Copies a folder and its contents into another folder.
    """
    # Create a copy of the folder object with a new primary key (to avoid conflicts)
    folder_copy = folder
    folder_copy.pk = None
    folder_copy.parent = destination_folder
    folder.urlhash=id_generator_2()
    folder_copy.save()
    for subfolder in folder.children.all():
        copy_folder_with_contents(subfolder, folder_copy)

    copy_files(folder.files.all(), folder_copy)