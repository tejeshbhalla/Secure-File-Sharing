from celery import shared_task
from django.core.mail import send_mail
from django.core.cache import cache
from content.utils import get_video_status,get_video_otp,get_upload_info,upload_video,delete_all_drm
from .models import Link_Model,Files_Model


@shared_task
def upload_video_to_vdocipher(obj_file_hash,obj_link_hash):
    obj_file=Files_Model.objects.get(urlhash=obj_file_hash)
    obj_link=Link_Model.objects.get(link_hash=obj_link_hash)
    key=f'{obj_file.urlhash}_{obj_link.link_hash}_video'
    value=cache.get(key)
    if value:
        pass
    else:
        cache.set(key, True,timeout=600)
        delete_all_drm(obj_link)
        if get_upload_info(obj_file):
           if upload_video(obj_link,obj_file):
               return True
    return False





