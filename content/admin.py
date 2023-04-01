from django.contrib import admin
from .models import Files_Model,Folder,Link_Model,Internal_Share,Link_logs,Internal_Share_Folders
# Register your models here.
@admin.register(Files_Model)
class AdminFilesModel(admin.ModelAdmin):
    pass

@admin.register(Folder)
class AdminFolder(admin.ModelAdmin):
    pass


@admin.register(Link_Model)
class AdminLink(admin.ModelAdmin):
    pass

@admin.register(Internal_Share)
class Internal_Share(admin.ModelAdmin):
    pass

@admin.register(Link_logs)
class LinkLogsModel(admin.ModelAdmin):
    pass

@admin.register(Internal_Share_Folders)
class Folder_Internal_Share(admin.ModelAdmin):
    pass