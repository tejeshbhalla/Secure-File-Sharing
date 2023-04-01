from django.contrib import admin
from .models import NewUser,BlacklistedToken, Notifications,Otp_Token,People_Groups,User_logs,Group_Permissions,Tenant,Basic_Plan,Premium_Plan
# Register your models here.
@admin.register(NewUser)
class AdminModelUser(admin.ModelAdmin):
    pass

@admin.register(BlacklistedToken)
class AdminBlackToken(admin.ModelAdmin):
    pass

@admin.register(Otp_Token)
class Otp_Token(admin.ModelAdmin):
    pass


@admin.register(People_Groups)
class AdminPeople_Groups(admin.ModelAdmin):
    pass

@admin.register(User_logs)
class AdminModelUser_Logs(admin.ModelAdmin):
    pass

@admin.register(Notifications)
class Notification_User(admin.ModelAdmin):
    pass

@admin.register(Group_Permissions)
class Group_Permission_Admin(admin.ModelAdmin):
    pass

@admin.register(Tenant)
class Tenant_Admin(admin.ModelAdmin):
    pass

@admin.register(Basic_Plan)
class Basic_Plan(admin.ModelAdmin):
    pass

@admin.register(Premium_Plan)
class Premium_Plan(admin.ModelAdmin):
    pass