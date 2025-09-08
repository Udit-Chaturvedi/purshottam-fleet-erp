# backend/apps/users/admin.py

from django.contrib import admin
from django.utils.translation import gettext_lazy as _
from django.utils.html import format_html
from django.urls import reverse

from apps.users.models import User, UserProfile, Role, OTP, DeletionRequest


@admin.register(Role)
class RoleAdmin(admin.ModelAdmin):
    list_display = ("name", "description")
    search_fields = ("name", "description")
    ordering = ("name",)
    readonly_fields = ("id",)
    fieldsets = (
        (None, {"fields": ("name", "description")}),
    )


class UserProfileInline(admin.StackedInline):
    model = UserProfile
    fk_name = "user"
    can_delete = False
    verbose_name = _("User Profile")
    verbose_name_plural = _("User Profiles")
    readonly_fields = ("employee_id", "is_active", "is_deleted", "created_at", "updated_at", "created_by")
    fields = (
        "employee_id",
        "phone",
        "avatar_preview",
        "avatar",
        "roles",
        "created_by",
        "is_active",
        "is_deleted",
        "force_password_reset",
        "created_at",
        "updated_at",
    )
    filter_horizontal = ("roles",)

    def avatar_preview(self, obj):
        if obj.avatar:
            return format_html(
                '<img src="{}" style="height: 50px; width: 50px; border-radius: 50%;" />',
                obj.avatar.url,
            )
        return "-"
    avatar_preview.short_description = _("Avatar Preview")


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    inlines = (UserProfileInline,)
    list_display = (
        "username",
        "email",
        "first_name",
        "last_name",
        "is_active",
        "profile_link",
        "date_joined",
        "last_login",
    )
    list_filter = ("is_active", "date_joined", "last_login", "profile__roles__name")
    search_fields = ("username", "email", "first_name", "last_name", "profile__employee_id", "profile__phone")
    ordering = ("username",)
    readonly_fields = ("date_joined", "last_login", "uuid")
    actions = ["soft_delete_users", "restore_users"]

    def profile_link(self, obj):
        if hasattr(obj, "profile") and obj.profile:
            url = reverse("admin:users_userprofile_change", args=[obj.profile.pk])
            return format_html('<a href="{}">{}</a>', url, obj.profile.employee_id)
        return "-"
    profile_link.short_description = _("Employee ID")

    def soft_delete_users(self, request, queryset):
        count = 0
        for user in queryset:
            if user.profile and not user.profile.is_deleted:
                user.profile.soft_delete()
                count += 1
        self.message_user(
            request,
            _("%d user profile(s) successfully soft deleted.") % count,
            level="info",
        )
    soft_delete_users.short_description = _("Soft delete selected users")

    def restore_users(self, request, queryset):
        count = 0
        for user in queryset:
            if user.profile and user.profile.is_deleted:
                user.profile.restore()
                count += 1
        self.message_user(
            request,
            _("%d user profile(s) successfully restored.") % count,
            level="info",
        )
    restore_users.short_description = _("Restore selected users")


@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = (
        "employee_id",
        "user_link",
        "phone",
        "is_active",
        "is_deleted",
        "force_password_reset",
        "created_by_link",
        "created_at",
        "updated_at",
    )
    list_filter = ("is_active", "is_deleted", "roles__name", "created_at", "updated_at")
    search_fields = ("employee_id", "phone", "user__username", "user__email", "created_by__username")
    ordering = ("employee_id",)
    readonly_fields = ("employee_id", "created_at", "updated_at")
    filter_horizontal = ("roles",)
    actions = ["soft_delete_profiles", "restore_profiles"]

    def user_link(self, obj):
        if obj.user:
            url = reverse("admin:users_user_change", args=[obj.user.pk])
            return format_html('<a href="{}">{}</a>', url, obj.user.username)
        return "-"
    user_link.short_description = _("Username")

    def created_by_link(self, obj):
        if obj.created_by:
            url = reverse("admin:users_user_change", args=[obj.created_by.pk])
            return format_html('<a href="{}">{}</a>', url, obj.created_by.username)
        return "-"
    created_by_link.short_description = _("Created By")

    def soft_delete_profiles(self, request, queryset):
        count = 0
        for profile in queryset:
            if not profile.is_deleted:
                profile.soft_delete()
                count += 1
        self.message_user(
            request,
            _("%d user profile(s) successfully soft deleted.") % count,
            level="info",
        )
    soft_delete_profiles.short_description = _("Soft delete selected user profiles")

    def restore_profiles(self, request, queryset):
        count = 0
        for profile in queryset:
            if profile.is_deleted:
                profile.restore()
                count += 1
        self.message_user(
            request,
            _("%d user profile(s) successfully restored.") % count,
            level="info",
        )
    restore_profiles.short_description = _("Restore selected user profiles")


@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ("user", "otp_code", "purpose", "is_used", "created_at", "expires_at")
    list_filter = ("is_used", "purpose", "created_at", "expires_at")
    search_fields = ("user__username", "otp_code")
    ordering = ("-created_at",)


@admin.register(DeletionRequest)
class DeletionRequestAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "requester_link",
        "target_user_profile_link",
        "reason",
        "is_approved",
        "approved_by_link",
        "created_at",
        "approved_at",
    )
    list_filter = ("is_approved", "created_at", "approved_at")
    search_fields = ("requester__username", "target_user_profile__employee_id", "reason")
    ordering = ("-created_at",)
    readonly_fields = ("id", "created_at", "approved_at")

    def requester_link(self, obj):
        if obj.requester:
            url = reverse("admin:users_user_change", args=[obj.requester.pk])
            return format_html('<a href="{}">{}</a>', url, obj.requester.username)
        return "-"
    requester_link.short_description = _("Requester")

    def target_user_profile_link(self, obj):
        if obj.target_user_profile:
            url = reverse("admin:users_userprofile_change", args=[obj.target_user_profile.pk])
            return format_html('<a href="{}">{}</a>', url, obj.target_user_profile.employee_id)
        return "-"
    target_user_profile_link.short_description = _("Target UserProfile")

    def approved_by_link(self, obj):
        if obj.approved_by:
            url = reverse("admin:users_user_change", args=[obj.approved_by.pk])
            return format_html('<a href="{}">{}</a>', url, obj.approved_by.username)
        return "-"
    approved_by_link.short_description = _("Approved By")