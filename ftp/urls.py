from django.urls import re_path as url
from django.urls import include,path
from .views import  List_Google_Drive_Folders,Start_Sync,List_One_Drive,Post_Code_OneDrive,Create_Remote_Server_OneDrive,Create_Remote_Server, Create_Sync_Direction, Delete_Server, Get_Code_Access_From_Server,Get_User_Servers, List_Google_Folders, Post_Code

app_name='sync_app'
urlpatterns = [
    path("create_server_googledrive",Create_Remote_Server.as_view(),name='create_remote_server'),
    path('create_server_onedrive',Create_Remote_Server_OneDrive.as_view(),name='onedrive_server'),
    path('get_user_servers',Get_User_Servers.as_view(),name='get_user_servers'),
    path('create_sync',Create_Sync_Direction.as_view(),name='sync direction'),
    path('google_drive/get_token',Post_Code.as_view(),name='post code'),
    path('get_access_token/<str:server_name>',Get_Code_Access_From_Server.as_view(),name='get_access_token'),
    path('get_google_folder/<str:server_name>/<str:id>',List_Google_Folders.as_view(),name='list google folders'),
    path('delete/<str:server_name>',Delete_Server.as_view(),name='delete server'),
    path("get_token",Post_Code_OneDrive.as_view(),name='postcodeonedrive'),
    path("list_onedrive_folders/<str:server_name>/<str:id>",List_One_Drive.as_view(),name='list_folders_onedrive'),
    path("list_googledrive_folders/<str:server_name>/<str:id>",List_Google_Drive_Folders.as_view(),name='list_folders_onedrive'),
    path('start_sync/<str:server_name>',Start_Sync.as_view(),name='post code'),
]

