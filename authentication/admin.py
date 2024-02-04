from django.contrib import admin
from .models import User, PasswordResetToken


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    search_fields = ['first_name', 'last_name']
    ordering = ["username"]
    list_display = ['username', 'first_name', 'last_name', 'email']
    list_editable = list_display[1:]


admin.site.register(PasswordResetToken)
