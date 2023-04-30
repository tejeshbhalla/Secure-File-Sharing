import sys 
import requests
import os
import io
from azure.storage.blob import BlobServiceClient, BlobClient, ContainerClient,ContentSettings
import django
import os
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(BASE_DIR)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Varency.settings')
import django
django.setup()
from files.models import NewUser
from content.models import Folder,Files_Model
from content.utils import create_notifications

def create_content(filename,username,path,urlhash):

    owner=NewUser.objects.get(username=username)
    parent_folder=Folder.objects.get(urlhash=urlhash)
    all_paths=path.split('\\')[3:-1]
    file_obj=path
    for i in all_paths:
                folder=Folder.objects.filter(name=i,parent=parent_folder)
                if len(folder)==0:
                    folder=Folder(name=i,parent=parent_folder,owner=owner)
                    folder.save()
                    parent_folder=folder
                else:
                    folder=folder.first()
                    parent_folder=folder
    file_instance=Files_Model.objects.filter(file_name=filename,folder=parent_folder)
    if len(file_instance)==0:
       file_instance = Files_Model(file_name=filename, owner=owner, folder=parent_folder)
       file_instance.content.name=file_obj
       file_instance.save()
       create_notifications(file_instance,extras=f'Synced file {file_instance.file_name}',type='Sync')
    else:
       file_instance = file_instance[0]
       file_instance.content.name=file_obj
       file_instance.save()
       create_notifications(file_instance,extras=f'Synced file {file_instance.file_name}',type='Sync')
                     



def download_and_upload_folder_onedrive(azure_connection_string,container_name,access_token,folder_path,parent_id=None,sub_path=None):
    onedrive_api = "https://graph.microsoft.com/v1.0/me/drive/items/{folder}/{action}"
    headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json"
    }
    
    # Get the list of items in the folder
    url = onedrive_api.format(folder=folder_path, action="children")
    response = requests.get(url, headers=headers)
    # Iterate over the items in the folder
    for item in response.json()["value"]:
        item_id = item["id"]
        item_name = item["name"]
        item_path = os.path.join(folder_path, item_name)
        # If the item is a folder, recursively call this function
        if not (len(item_name.split('.'))>1):
            download_and_upload_folder_onedrive(azure_connection_string,container_name,access_token,item_id, parent_id=item,sub_path=sub_path+'\\'+item_name)
        # If the item is a file, download and upload it to Blob storage
        else:
            # Download and upload the file content in chunks
            chunk_size = 40*1024 * 1024 # 4 MB
            download_url = item['@microsoft.graph.downloadUrl']
            #response = requests.get(download_url, headers=headers, stream=True)
            blob_service_client = BlobServiceClient.from_connection_string(
                    azure_connection_string)
            if sub_path:
                   item_path=sub_path+'\\'+item_path
            blob_client = blob_service_client.get_blob_client(
            container=container_name, blob=item_path)
            try:
                blob_client.get_blob_properties()
                blob_client.delete_blob()
            except Exception as e:
                if e.status_code == 404:
                    blob_client.create_append_blob()
            byte_range_start = 0
            byte_range_end = chunk_size - 1
            while True:
                headers_with_range = headers.copy()
                headers_with_range["Range"] = "bytes={}-{}".format(byte_range_start, byte_range_end)
                response = requests.get(download_url, headers=headers_with_range, stream=True)
                chunk = response.content
                if not chunk:
                    break
                blob_client.upload_blob(chunk, blob_type="AppendBlob")
                byte_range_start += chunk_size
                byte_range_end += chunk_size
            blob_client.upload_blob(b'', blob_type="AppendBlob")
            arr=item_path.split('\\')
            create_content(item_name,arr[0],item_path,arr[2])

def download_and_upload_folder_google(azure_connection_string, container_name, access_token, folder_path, parent_id=None, sub_path=None):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # Get the list of items in the folder
    url = f"https://www.googleapis.com/drive/v3/files?q='{folder_path}'+in+parents&fields=files(id,name,mimeType)"
    response = requests.get(url, headers=headers)
    # Iterate over the items in the folder
    for item in response.json()["files"]:
        item_id = item["id"]
        item_name = item["name"]
        item_path = os.path.join(folder_path, item_name)
        # If the item is a folder, recursively call this function
        if item["mimeType"] == "application/vnd.google-apps.folder":
            download_and_upload_folder_google(azure_connection_string, container_name, access_token, item_id, parent_id=item, sub_path=sub_path + '\\' + item_name)
        # If the item is a file, download and upload it to Blob storage
        else:
            # Download and upload the file content in chunks
            chunk_size = 40* 1024 * 1024  # 4 MB
            download_url = f"https://www.googleapis.com/drive/v3/files/{item_id}?alt=media"
            blob_service_client = BlobServiceClient.from_connection_string(azure_connection_string)
            if sub_path:
                item_path = sub_path + '\\' + item_path
            blob_client = blob_service_client.get_blob_client(container=container_name, blob=item_path)

            try:
                blob_client.get_blob_properties()
                blob_client.delete_blob()
            except Exception as e:
                if e.status_code == 404:
                    blob_client.create_append_blob()
            byte_range_start = 0
            byte_range_end = chunk_size - 1
            while True:
                headers_with_range = headers.copy()
                headers_with_range["Range"] = f"bytes={byte_range_start}-{byte_range_end}"
                response = requests.get(download_url, headers=headers_with_range, stream=True)
                chunk = response.content
                if not chunk or response.status_code!=206:
                    break
                blob_client.upload_blob(chunk, blob_type="AppendBlob", content_settings=ContentSettings(content_type=response.headers["content-type"]))
                byte_range_start += chunk_size
                byte_range_end += chunk_size
            blob_client.upload_blob(b'', blob_type="AppendBlob")
            arr = item_path.split('\\')
            create_content(item_name, arr[0], item_path, arr[2])



def call():
    arg1=sys.argv
    folder_to_sync=arg1[1]
    folder_in=arg1[2]
    username=arg1[3]
    access_token=arg1[4]
    connection_string=arg1[5]
    container_name=arg1[6]
    type=arg1[7]
    if type=='googledrive':
        download_and_upload_folder_google(connection_string,container_name,access_token,folder_path=folder_to_sync,sub_path=f'{username}\\googledrive\\{folder_in}')
    else:
        download_and_upload_folder_onedrive(connection_string,container_name,access_token,folder_path=folder_to_sync,sub_path=f'{username}\\onedrive\\{folder_in}')


call()
