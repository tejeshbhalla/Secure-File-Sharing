from .views import Upload_Folder_New,Copy_File_Folder,Revert_Versions_File,Check_Versions_File,Multi_File_Upload,Download_Multi_File_Folder_Link,Download_Multi_File_Folder,Download_Folder_View,Get_File_Link_Detail,Get_File_Detail,MediaStreamView,Add_Link_Favourite,SearchBar,Approve_Link, Check_Link_Exist, CreateFolderView, Deleted_Folder_Details_All,FolderDetailView,CreateFilesView, Internal_File_Notification, Internal_Folder_Detail, Link_Count_Dashboard, Links_By_Date, Permenently_Delete, Recently_Acessed, Recently_Acessed_Get, Recover_Files_Folders, Request_File_Create, Request_File_Upload, Sos_Link, Storage_Share, Upload_Folder,View_File,Share_File_Link,Visit_File_Link,Share_Folder,Visit_File_Link_Client,Remove_Shared,Shared_Links_Detail,Delete_Link,Share_File,MoveFolder,Delete_Multi_Files_Folders,Get_Link_Logs, send_file
from django.urls import re_path as url
from django.urls import include,path


app_name='content_app'
urlpatterns = [
    path("folder_create",CreateFolderView.as_view(),name="folder_create"),
    path("folder_update/<str:urlhash>",CreateFolderView.as_view(),name="folder_update"),
    path("folder_detail/<str:urlhash>",FolderDetailView.as_view(),name="folder_detail"),
    path("folder_delete/<str:urlhash>",CreateFolderView.as_view(),name="folder_delete"),
    path("file_create/<str:urlhash>",CreateFilesView.as_view(),name="file_create"),
    path("file_delete/<str:urlhash>",CreateFilesView.as_view(),name="file_create"),
    path("file/<str:url_file>",View_File.as_view(),name="view_file"),
    path("share_file_link",Share_File_Link.as_view(),name="share_file_link"),
    path("link_file/visit/<str:link_hash>",Visit_File_Link.as_view(),name="share_file_link_visit"),
    path("share_folders",Share_Folder.as_view(),name="share_folders"),
    path("link_file/visit/client/<str:link_hash>/<str:folder_hash>",Visit_File_Link_Client.as_view(),name="client link visit client"),
    path("shared_links_detail",Shared_Links_Detail.as_view(),name="shared_links_details"),
    path("delete_link",Delete_Link.as_view(),name="delete_link"),
    path("internalshare",Share_File.as_view(),name="internalshare"),
    path("move_folder",MoveFolder.as_view(),name='move_folder'),
    path("check_delete",Delete_Multi_Files_Folders.as_view(),name="delete multiple files and folders"),
    path("upload_folder",Upload_Folder_New.as_view(),name='upload_folder'),
    path("multi_file_upload",Multi_File_Upload.as_view(),name='upload_files'),
    path("link_logs/<str:link_hash>",Get_Link_Logs.as_view(),name="link_logs"),
    path("check/link/<str:link_hash>",Check_Link_Exist.as_view(),name='check link'),
    path("deleted/all_content",Deleted_Folder_Details_All.as_view(),name='deleted folders and files'),
    path('deleted/recover',Recover_Files_Folders.as_view(),name='recover files and folders'),
    path('request/file_upload/<str:urlhash>',Request_File_Upload.as_view(),name='request file upload'),
    path("file/internal_file",Internal_File_Notification.as_view(),name='create log for internal share view file'),
    path('request/create_request',Request_File_Create.as_view(),name='create request'),
    path('request/delete_request/<str:urlhash>',Request_File_Create.as_view(),name='delete request'),
    path('deleted/permenently_delete',Permenently_Delete.as_view(),name='permenently delete'),
    path("file_update/<str:urlhash>",CreateFilesView.as_view(),name='update file'),
    path('internal/notification/<str:file_hash>',Internal_File_Notification.as_view(),name='internal notification'),
    path('dashboard/link_count',Link_Count_Dashboard.as_view(),name='link count dashboard'),
    path('internal/folder_detail/<str:urlhash>',Internal_Folder_Detail.as_view(),name='internal_folder_detail'),
    path('internal/remove_user/<str:urlhash>',Share_File.as_view(),name='remove user from internal share'),
    path('internal/edit_user/<str:urlhash>',Share_File.as_view(),name='edit user details'),
    path('dashboard/storage_share',Storage_Share.as_view(),name='storage_share'),
    path('logo/<str:urlhash>',send_file,name='view logo'),
    path('link/approvelink/<str:urlhash>',Approve_Link.as_view(),name='approve link'),
    path('dashboard/soslink',Sos_Link.as_view(),name='sos link'),
    path('dashboard/linkgraph',Links_By_Date.as_view(),name='link graph'),
    path('remove/shared',Remove_Shared.as_view(),name='remove shared'),
    path('dashboard/search/<str:type>/<str:query>',SearchBar.as_view(),name='searchbarcontent'),
    path('link/add_favourite/<str:link_hash>',Add_Link_Favourite.as_view(),name='add link favourite'),
    path("media/<str:token>",MediaStreamView.as_view(),name='media stream'),
    path('file_detail/<str:obj_hash>/<str:file_hash>/<str:type>',Get_File_Detail.as_view(),name='file_detail'),
    path('file_detail/link/<str:obj_hash>/<str:file_hash>/<str:type>',Get_File_Link_Detail.as_view(),name='file_detail'),
    path('folder_download/<str:token>',Download_Folder_View.as_view(),name='download folder'),
    path('download_multi_file_folder/<str:type>',Download_Multi_File_Folder.as_view(),name='download multi files and folders'),
    path('download_multi_file_folder/link',Download_Multi_File_Folder_Link.as_view(),name='download multi files and folders link'),
    path('get_file_versions/<str:urlhash>',Check_Versions_File.as_view(),name='check file versions'),
    path('revert_version/<str:urlhash>',Revert_Versions_File.as_view(),name='revert file version'),
    path('copy_files_folder',Copy_File_Folder.as_view(),name='copy files folders'),
    ]

