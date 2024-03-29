import random 
import string
import jwt
from django.conf import settings
from files.models import NewUser
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
import os
from multiprocessing import Process
import boto3
from boto.s3.connection import S3Connection
from files.models import Notifications
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from azure.storage.blob import BlobServiceClient, ContainerClient,generate_blob_sas, BlobSasPermissions,BlobClient
from Varency.settings import SECRET_KEY,AZURE_ACCOUNT_NAME
from datetime import datetime, timedelta
from Varency.settings import AZURE_ACCOUNT_KEY,CONVERTER_URL,LOCAL_STORAGE_PATH,FRONT_END_URL,EXPIRY_SAS_TIME,BACKEND_URL,EMAIL_HOST_USER,AZURE_CONNECTION_STRING,AZURE_CONTAINER,API_SECRET_KEY,UPLOAD_URL_VDOCIPHER
import base64
import json
import requests
from requests_toolbelt import MultipartEncoder
from django.core.cache import cache
import re
from django.core.exceptions import ValidationError
from time import sleep
from urllib.parse import urlencode
from azure.core.exceptions import ResourceNotFoundError
from Crypto.Cipher import AES
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import ast
from django.core.files.base import ContentFile
import pyAesCrypt
from io import BytesIO
import tempfile


def recursive_move_folder(folder):
    if folder.parent==None:
        return []
    pass



def delete_folder(obj):
    files=obj.files.all()
    for f in files:
        f.delete()
    return 


def send_email(emails,link,hash,password,owner,prevent_forwarding):
    for i in emails:
        logolink=f'{BACKEND_URL}/api/api/content/logo/{hash}'
        encoded = base64.b64encode(i.encode('ascii'))
        link+='?'+str(encoded)
        
        if prevent_forwarding:
            html_content=render_to_string(r"linkhtml.html",{'logolink':logolink,"link":link,"password":password,"sent_email":owner,"arialabel":'pbverfi66','arialabel2':'pbverfi99',"name":i.split('@')[0]})
        else:
            link_logo="https://gncgiu.stripocdn.email/content/guids/CABINET_8915327aedd3480f87b0ee4a1fad6050cdcd18fc48b8bd548d3777dcaaf927e2/images/zyroimage.png"
            html_content=render_to_string(r"linkhtml.html",{'logolink':link_logo,"link":link,"password":password,"sent_email":owner,"arialabel":'NAN','arialabel2':'NAN',"name":i.split('@')[0]})
        text_content=strip_tags(html_content)
    
        email=EmailMultiAlternatives('Mail from Varency',text_content,EMAIL_HOST_USER,[i])

        email.attach_alternative(html_content,'text/html')
        email.send()




def send_mail_helper(emails,link,hash,password,owner,prevent_forwarding):
    p=Process(target=send_email,args=(emails,link,hash,password,owner,prevent_forwarding))
    p.run()
    return 



def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))





def get_user(request,token=''):
    if len(token)==0:
        auth=request.headers.get('Authorization').split(' ')
        token=auth[1]
    payload=jwt.decode(token,settings.SECRET_KEY,algorithms=['HS256',])
    username=payload.get('username')
    return username


def upload_path(instance, filename):
    if instance.folder==None:
        path=""
        pathstr=""
    else:
        path=instance.folder.order_parent_urlhash()
        pathstr=''
        for i in path:
            pathstr+=i+'/'
    path = os.path.join(settings.MEDIA_ROOT, str(instance.owner.username),pathstr,instance.urlhash)
    if not os.path.isdir:
        os.mkdir(path)

    return os.path.join(path, filename)


def upload_path_folder(instance):
    path=instance.order_parent()
    path_str=""
    path_str+=f'{instance.owner.username}/root/'
    for i in path:
        path_str+=i+'/'
    return path_str




def delete_keys(obj):
    blob_service_client = BlobServiceClient.from_connection_string(conn_str=AZURE_CONNECTION_STRING)
    blob_client = blob_service_client.get_container_client(AZURE_CONTAINER)
    #container_client = ContainerClient.from_connection_string(conn_str=AZURE_CONNECTION_STRING, container_name=AZURE_CONTAINER)
    if obj.folder:
        path_str=f'{obj.owner.username}/root/'
        path=obj.folder.order_parent()
        for i in path:
            path_str+=i+'/'
    else:
        path_str=f'{obj.owner.username}/{obj.urlhash}'
    #path_str+='/'+obj.file_name
    for blob in blob_client.list_blobs(name_starts_with=path_str):
    	blob_client.delete_blob(blob.name)
    #container_client.delete_blob(blob=path_str)

def get_all_versions(obj):
    path_of_file=upload_path(obj,obj.file_name)
    session = boto3.Session(
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
    s3 = session.resource('s3')
    bucket = s3.Bucket(AWS_STORAGE_BUCKET_NAME)
    versions = bucket.object_versions.filter(Prefix=path_of_file)
    
    all_versions=[]
    for version in versions:
        obj = version.get()
        all_versions.append([obj.get('VersionId'), obj.get('ContentLength'), obj.get('LastModified')])
    return all_versions






def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip



def create_notifications(instance,extras='',type=''):
    name=instance.__class__.__name__
    if 'Internal' in name:
        users=instance.shared_with.all()
        owner=instance.owner
        for i in users:
            n=Notifications(user=i,text=f'{owner.email} shared files/folders with you',type='Shared')
            n.save()
    if 'Link' in name:
        owner=instance.owner
        name=instance.name
        n=Notifications(user=owner,text=f'{name} link accessed by {extras["ip"]}',type='Link')
        n.save()
    if 'User' in name:
        owner=instance
        n=Notifications(user=owner,text=extras,type='Personal')
        n.save()
    if type=='Sync':
        owner=instance.owner
        n=Notifications(user=owner,text=extras,type=type)
        n.save()


    


def link_auth_check(obj,password=''):
    owner=obj.owner
    if not owner.is_active:
        return False
    if not obj.is_approved:
        return False
    if obj.password!=password:
        return False
    

def fetch_versions(file):
    
    # Create a BlobServiceClient object using the connection string
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
    # Get a ContainerClient object for the container
    container_client = blob_service_client.get_container_client(AZURE_CONTAINER)
    # Get a list of all versions of the blob
    versions = container_client.list_blobs(name_starts_with=file.content.name, include=["versions"])
    if file.metadata:
        metadata=json.loads(file.metadata)
    else:
        metadata=[]
    d={}
    for i in metadata:
        for j in i:
            d[j]=i[j]
    data=[]
    for version in versions:
        data.append({'metadata':d[version.version_id] if version.version_id in d else None,'is_current_version':version.is_current_version,'size':version.size,'last_modified':version.last_modified,'id':version.version_id})
    return data

def set_current_version(file, current_version, target_version_id):
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
    current_blob = blob_service_client.get_blob_client(container=AZURE_CONTAINER, blob=file.content.name)
    properties = current_blob.get_blob_properties()
    current_version_id = properties.metadata.get('versionid')
    older_blob = BlobClient.from_blob_url(
        blob_url=f"https://{AZURE_ACCOUNT_NAME}.blob.core.windows.net/{AZURE_CONTAINER}/{file.content.name}?{urlencode({'versionid': target_version_id})}",
        credential=AZURE_ACCOUNT_KEY
    )
    content = older_blob.download_blob().content_as_bytes()
    try:
        file_content=ContentFile(content,file.file_name)
        file.content=file_content
        file.resave()
    except ResourceNotFoundError:
        return False
    return True


def download_url_generate_sas(obj,ip):
    
    blob_service_client = BlobServiceClient.from_connection_string(conn_str=AZURE_CONNECTION_STRING)
    blob_client = blob_service_client.get_blob_client(container=AZURE_CONTAINER,blob=obj.content.name)
    start_time = datetime.utcnow()
    expiry_time = start_time + timedelta(minutes=EXPIRY_SAS_TIME)
    permissions = BlobSasPermissions(read=True)
    content_disposition = f"attachment; filename={obj.file_name}"
    name=obj.content.name
    name = re.sub(r"\\", "/", name)
    sas_token = generate_blob_sas(
    account_name=blob_service_client.account_name,
    account_key=blob_service_client.credential.account_key,
    container_name=AZURE_CONTAINER,
    blob_name=name,
    permission=permissions,
    expiry=expiry_time,
    start=start_time,
    ip=ip,
    content_disposition=content_disposition,
    referer=f'https://{obj.owner.tenant.subdomain}.{FRONT_END_URL}',
    cachecontrol="private, max-age=0, no-cache, no-store"
    )
    sas_url = f"{blob_client.url}?{sas_token}"
    return sas_url



def check_permissions(self):
    tenant=self.owner.tenant
    if tenant.plan_type=='Basic':
        plan=tenant.basic_plan
        can_link_log=plan.can_link_log
        can_add_date_to_link=plan.can_add_date_to_link
        can_access_limit=plan.can_access_limit
        has_proctored_link=plan.has_proctored_link
        has_email_forwarding=plan.has_email_forwarding
        has_link_password=plan.has_link_password

    if tenant.plan_type=='Premium':
        plan=tenant.premium_plan
        can_link_log=plan.can_link_log
        can_add_date_to_link=plan.can_add_date_to_link
        can_access_limit=plan.can_access_limit
        has_proctored_link=plan.has_proctored_link
        has_email_forwarding=plan.has_email_forwarding
        has_link_password=plan.has_link_password
    d={'can_link_log':can_link_log,'can_add_date_to_link':can_add_date_to_link,'can_access_limit':can_access_limit,'has_proctored_link':has_proctored_link,
    'has_email_forwading':has_email_forwarding,'has_link_password':has_link_password}
    return d



class RangeFileWrapper(object):
    def __init__(self, filelike, blksize=8192, offset=0, length=None):
        self.filelike = filelike
        self.filelike.seek(offset, os.SEEK_SET)
        self.remaining = length
        self.blksize = blksize

    def close(self):
        if hasattr(self.filelike, 'close'):
            self.filelike.close()

    def __iter__(self):
        return self

    def __next__(self):
        if self.remaining is None:
            # If remaining is None, we're reading the entire file.
            data = self.filelike.read(self.blksize)
            if data:
                return data
            raise StopIteration()
        else:
            if self.remaining <= 0:
                raise StopIteration()
            data = self.filelike.read(min(self.remaining, self.blksize))
            if not data:
                raise StopIteration()
            self.remaining -= len(data)
            return data
        


def create_media_jwt(obj,ip):
    delta=timedelta(minutes=EXPIRY_SAS_TIME)
    token=jwt.encode({'hash':obj.urlhash,'exp':datetime.utcnow()+delta,'ip':ip},SECRET_KEY,algorithm='HS256')
    return token





def get_upload_info(obj):
    filename=obj.file_name.split('.')[-1]+'.avi'
    querystring = {"title":filename}

    url = UPLOAD_URL_VDOCIPHER
    headers = {
  'Authorization': "Apisecret " + API_SECRET_KEY
        }
    response = requests.request("PUT", url, headers=headers, params=querystring)
    if response.status_code==200:
        obj.uploadinfo=response.json()
        obj.save()
        return True
    return 




def validate_link_drm(obj):
    all_files=obj.file_hash.all()
    files_content = [obj.uploadinfo for obj in all_files if obj.uploadinfo]
    return len(files_content)

def delete_all_drm(obj):
    all_files=obj.file_hash.all()
    files_content = [obj for obj in all_files if obj.uploadinfo]
    video_ids=[obj.uploadinfo['videoId'] for obj in files_content]
    all_ids=','.join(video_ids)
    headers = {
    'Authorization': f"Apisecret {API_SECRET_KEY}",
    'Content-Type': "application/json",
    'Accept': "application/json"
    }
    querystring = {"videos":all_ids}
    response = requests.request("DELETE", UPLOAD_URL_VDOCIPHER, headers=headers, params=querystring)
    if response.status_code==200:
        all_files.update(uploadinfo=None)
        return True
    return False


def cache_file_path(key,file_path):
    cache.set(key, file_path, timeout=7200) # cache for 2 hours
    return key

def get_cached_file_path(key):
    file_path = cache.get(key)
    if file_path:
        os.remove(file_path) # delete the file from local storage
        cache.delete(key) # delete the cache key
    return file_path



def convert_to_mp4_helper(binary,path):
    url = CONVERTER_URL
    files = {'file': binary}
    response = requests.post(url, files=files)

    with open(path,'wb') as file:
        file.write(response.content)
    return response.content


def convert_file_to_mp4(obj_link,obj_file):
    key=f'{obj_link.link_hash}_{obj_file.urlhash}'
    value=cache.get(key)
    if value:
        with open(value,'rb') as file:
            #print(file.read())
            return value
    else:
        url=obj_file.content.url
        r=requests.get(url)
        file_name=obj_file.file_name.split('.')
        file_name=file_name[0]+'.avi'
        path=LOCAL_STORAGE_PATH+'/'+file_name
        data=convert_to_mp4_helper(r.content,path)
        cache_file_path(key,path)
        return cache.get(key)
    return None


def set_poster(videoid):
    from django.templatetags.static import static
    static_file_url=static('Backend/static/images/thumbnail.png')
    url = f"https://dev.vdocipher.com/api/videos/{videoid}/files"

    with open(static_file_url, 'rb') as f:
        file_contents = f.read()

    payload = {
        'file': ('thumbnail.png', file_contents, 'image/png')
    }

    headers = {
        'Authorization': f"Apisecret {API_SECRET_KEY}",
        'Accept': "application/json"
    }

    response = requests.post(url, files=payload, headers=headers)

    return response

        


def upload_video(obj_link,obj_file):
    path=convert_file_to_mp4(obj_link,obj_file)
    uploadInfo = obj_file.uploadinfo
    clientPayload = uploadInfo['clientPayload']
    uploadLink = clientPayload['uploadLink']
    filename = obj_file.file_name.split('.')[0]+'.avi'  # use file name here

    m = MultipartEncoder(fields=[
        ('x-amz-credential', clientPayload['x-amz-credential']),
        ('x-amz-algorithm', clientPayload['x-amz-algorithm']),
        ('x-amz-date', clientPayload['x-amz-date']),
        ('x-amz-signature', clientPayload['x-amz-signature']),
        ('key', clientPayload['key']),
        ('policy', clientPayload['policy']),
        ('success_action_status', '201'),
        ('success_action_redirect', ''),
        ('file', (filename, open(path,'rb'), 'text/plain'))
        ])
    response = requests.post(
    uploadLink,
    data=m,
    headers={'Content-Type': m.content_type}
    )
    if response.ok:
        set_poster(uploadInfo['videoId'])
        return True
    else:
        return False


def get_video_status(obj):
    url=UPLOAD_URL_VDOCIPHER
    video_id=obj.uploadinfo['videoId']
    url+='/'+video_id
    headers = {
    'Authorization': f"Apisecret {API_SECRET_KEY}",
    'Content-Type': "application/json",
    'Accept': "application/json"
    }

    response = requests.request("GET", url, headers=headers)
    data=response.json()
    if 'status' in data and data['status']=='ready':
        return True
    else:
        return False
    

def get_video_otp(obj):
    if obj.uploadinfo:
        id=obj.uploadinfo['videoId']
        url=UPLOAD_URL_VDOCIPHER+'/'+id+'/'+'otp'
        payload = json.dumps({'ttl': 300})
        headers = {
            'Authorization': f"Apisecret {API_SECRET_KEY}",
            'Content-Type': "application/json",
            'Accept': "application/json"
            }
        response = requests.request("POST", url, data=payload, headers=headers)
        data=response.json()
        otp=data['otp']
        playbackinfo=data['playbackInfo']
        return f'https://player.vdocipher.com/v2/?otp={otp}&playbackInfo={playbackinfo}&controls=off'
    return None




def validate_share(internal_share,data):
    can_add_delete_content=data['can_add_delete_content']
    can_share_content=data['can_share_content']
    can_download_content=data['can_download_content']
    is_proctored=data['is_proctored']
    if not internal_share.can_add_delete_content and can_add_delete_content:
        raise ValidationError('Invalid privelages cant have permission you dont own')
    if not internal_share.can_share_content and can_share_content:
        raise ValidationError('Invalid privelages cant have permission you dont own')
    if not internal_share.can_download_content and can_download_content:
        raise ValidationError('Invalid privelages cant have permission you dont own')
    if not internal_share.is_proctored and is_proctored:
        raise ValidationError('Invalid privelages cant have permission you dont own')
    



def encrypt_with_aes(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext




def key_decode(obj):
    key_bytes = bytes(obj.key)
    # Convert the key value from a byte string to a string
    key_str = key_bytes.decode('utf-8')

    # Use the ast.literal_eval() function to safely evaluate the string
    key_value = ast.literal_eval(key_str)

    # Create a new bytes object from the inner byte string
    key_bytes = bytes(key_value)

    return key_bytes




def get_current_version_id(file):
    # Create a BlobServiceClient object using the connection string
    blob_service_client = BlobServiceClient.from_connection_string(AZURE_CONNECTION_STRING)
    # Get a ContainerClient object for the container
    container_client = blob_service_client.get_container_client(AZURE_CONTAINER)
    # Get a list of all versions of the blob
    versions = container_client.list_blobs(name_starts_with=file.content.name, include=["versions"])
    for version in versions:
        if version.is_current_version:
            return version.version_id

    return None

def attach_file_metadata(message,file,version_id):
    if not file.metadata:
        metadata=[]
    else:
        metadata=json.loads(file.metadata)
    metadata.append({version_id:message})
    data=json.dumps(metadata)
    file.metadata=data
    file.save()
    

def convert_to_file(chunk):
    in_memory_file = BytesIO()
    in_memory_file.write(chunk)
    in_memory_file.seek(0)
    django_file = ContentFile(in_memory_file.read())
    in_memory_file.close()
    return django_file


def encrypt_chunk(chunk,buffer_size):
        # Set encryption parameters
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        temp_file.write(chunk)
        temp_file.close()
        password = "your_password_here"  # Set your own password
        file_in=convert_to_file(chunk)
        flag1=0
        with file_in:
            flag1=flag1+1
            flag2=str(flag1)+'.aes'
            with open(flag2, "wb") as file_out:
                pyAesCrypt.encryptStream(file_in, file_out, password, buffer_size)
        with open(flag2, 'rb') as encrypted_file:
            encrypted_chunk = encrypted_file.read()
            # Clean up the temporary and encrypted files
            #temp_file.unlink()
            encrypted_file.close()

            # Return the encrypted chunk or the path of the encrypted file
        os.remove(flag2)
        return encrypted_chunk  # or return encrypted_file_path
    
    
    
        

def decrypt_file(data,key):
    cipher_suite = Fernet(key)
    decrypted_data=cipher_suite.decrypt(data)
    return decrypted_data

