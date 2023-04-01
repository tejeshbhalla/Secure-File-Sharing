from django.contrib import admin
from .models import Server_Connection,Sync_Direction

# Register your models here.
@admin.register(Server_Connection)
class ServerConnectionAdmin(admin.ModelAdmin):
    pass

@admin.register(Sync_Direction)
class SyncDirectionAdmin(admin.ModelAdmin):
    pass

