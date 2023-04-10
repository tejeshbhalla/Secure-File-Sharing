from apscheduler.schedulers.background import BackgroundScheduler
from files.models import BlacklistedToken,Otp_Token,NewUser,Notifications
import datetime
import pytz
from content.models import Link_Model,Folder,Files_Model
from files.utils import no_of_recovery_days
from Varency.settings import AZURE_CONNECTION_STRING,AZURE_CONTAINER
from ftp.utils import check_and_refresh_token_onedrive
import json
import subprocess
from django.utils import timezone
import os
from Varency.settings import LOCAL_STORAGE_PATH
def clean_db():
    try:
        tokens=BlacklistedToken.objects.all()
        now=timezone.now()
        for token in tokens:
            if token.time_expired<now:
                token.delete()
    except Exception as e:
        pass
def clean_db_2():
    try:

        links=Link_Model.objects.all()
        now=timezone.now()
        for link in links:
            if link.expiry_date==None:
                continue
            if link.expiry_date<now:
                user=link.owner
                user.expired_link_count+=1
                user.save()
                link.deleted=True
                link.save()
    except Exception as e:
        pass


def clean_db_5():
    try:

        links=Link_Model.objects.all()
        now=timezone.now()
        for link in links:
            if link.deleted:
                if link.expiry_date-now>30:
                    user=link.owner
                    user.expired_link_count+=1
                    user.save()
                    link.delete()
                    link.save()
    except Exception as e:
        pass




def clean_db_3():
    try:

        all_tokens=Otp_Token.objects.all()
        now=timezone.now()
        for token in all_tokens:
            if token.time_expired<now:
                token.delete()
    except Exception as e:
        pass
def clean_db():
    try:
  
        tokens=BlacklistedToken.objects.all()
        now=timezone.now()
        for token in tokens:
            if token.time_expired<now:
                token.delete()
    except Exception as e:
        pass

def clean_db_4():
    try:

        tokens=Notifications.objects.all()
        now=timezone.now()
        for n in tokens:
            if n.date<now:
                n.delete()
    except Exception as e:
        pass

def active_login():
    try:
   
        obj=NewUser.objects.all()
        for i in obj:
            if i.last_access:
                time_delta=timezone.now()-i.last_access
            else:
                continue
            if i.token_value==None:
                continue
            if time_delta.seconds/3600/100>=2 and len(BlacklistedToken.objects.filter(token=i.token_value))==0:
                b_t=BlacklistedToken(token=i.token_value,user=i,time_expired=timezone.now())
                b_t.save()
    except Exception as e:
        pass


def trash_cleaner():
    try:
 
        all_folders=Folder.objects.all().filter(deleted=True)
        all_files=Files_Model.objects.all().filter(deleted=True)
        now=timezone.now()
        for i in all_files:
            no_of_days=no_of_recovery_days(i)
            now+=datetime.timedelta(days=no_of_days)
            if i.deleted:
                if now-i.last_deleted>=no_of_days:
                    i.delete()
        for j in all_folders:
            no_of_days=no_of_recovery_days(j)
            now+=datetime.timedelta(days=no_of_days)
            if j.deleted:
                if now-j.last_deleted>=no_of_days:
                    j.delete()
    except Exception as e:
       pass


def content_cleaner():
    try:
        dir_path = LOCAL_STORAGE_PATH

        # Get a list of all files in the directory
        files = os.listdir(dir_path)

        # Loop over the files and delete each one
        for file in files:
            file_path = os.path.join(dir_path, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
    except Exception as e:
        pass



    
def start():
    schedulers = BackgroundScheduler()
    schedulers.add_job(clean_db,'interval',hours=24,id='cleaner_001',replace_existing=True)
    schedulers.add_job(clean_db_2,'interval',minutes=1,id='cleaner_002',replace_existing=True)
    schedulers.add_job(clean_db_3,'interval',minutes=10,id='cleaner_003',replace_existing=True)
    schedulers.add_job(active_login,'interval',minutes=1,id='adder_001',replace_existing=True)
    schedulers.add_job(clean_db_4,'interval',hours=24,id='cleaner_004',replace_existing=True)
    schedulers.add_job(clean_db_5,'interval',hours=24,id='cleaner_004 link delete',replace_existing=True)
    schedulers.add_job(trash_cleaner,'interval',hours=2,id='delete run',replace_existing=True)
    schedulers.add_job(content_cleaner,'interval',hours=20,id='delete run',replace_existing=True)
    schedulers.start()