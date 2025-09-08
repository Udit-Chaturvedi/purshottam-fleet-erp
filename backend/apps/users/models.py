# backend/apps/users/models.py

import uuid
import re
from datetime import timedelta, datetime

from django.conf import settings
from django.contrib.auth.models import AbstractUser, UserManager
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator, FileExtensionValidator
from django.db import models, transaction
from django.db.models import Q, JSONField
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from django.dispatch import receiver

from apps.audit.models import AuditLog  # Assuming audit app provides AuditLog model


def avatar_upload_to(instance, filename):
    # Custom upload path: avatars/user_<uuid>/<filename>
    ext = filename.split('.')[-1]
    return f"avatars/user_{instance.user.uuid}/{instance.user.uuid}.{ext}"


def validate_file_size(file):
    max_size_mb = 5
    if file.size > max_size_mb * 1024 * 1024:
        raise ValidationError(f"File size must be under {max_size_mb}MB")


class Role(models.Model):
    """
    Role defines the RBAC roles and capabilities in the system.
    """
    class RoleName(models.TextChoices):
        OWNER = "owner", _("Owner")
        MANAGER = "manager", _("Manager")
        ACCOUNTANT = "accountant", _("Accountant")
        RTO_STAFF = "rto_staff", _("RTO Staff")
        DATA_ENTRY = "data_entry", _("Data Entry")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(
        max_length=32,
        choices=RoleName.choices,
        unique=True,
        db_index=True,
        help_text=_("Role identifier, unique across all roles"),
    )
    description = models.TextField(blank=True)

    class Meta:
        verbose_name = _("Role")
        verbose_name_plural = _("Roles")
        ordering = ["name"]

    def __str__(self):
        return self.get_name_display()


class UserQuerySet(models.QuerySet):
    def active(self):
        return self.filter(is_active=True, profile__is_deleted=False)

    def inactive(self):
        return self.filter(Q(is_active=False) | Q(profile__is_deleted=True))

    def not_deleted(self):
        return self.filter(profile__is_deleted=False)

    def deleted(self):
        return self.filter(profile__is_deleted=True)


class UserManagerWithSoftDelete(UserManager):
    """
    Manager supporting soft deletion filtering by default.
    """
    def get_queryset(self):
        return UserQuerySet(self.model, using=self._db).not_deleted()


class User(AbstractUser):
    """
    Custom User extending AbstractUser to add UUID and soft-deletion awareness.
    Soft deletion flag is on related UserProfile, filtering is coordinated via manager.
    """
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)

    # Use custom manager enforcing not_deleted filtering by default
    objects = UserManagerWithSoftDelete()
    all_objects = UserManager()  # includes deleted users

    def soft_delete(self):
        # Delegate soft deletion to profile for consistency
        if hasattr(self, "profile"):
            self.profile.soft_delete()

    def restore(self):
        if hasattr(self, "profile"):
            self.profile.restore()

    class Meta:
        verbose_name = _("User")
        verbose_name_plural = _("Users")
        ordering = ["username"]


class UserProfileQuerySet(models.QuerySet):
    def active(self):
        return self.filter(is_active=True, is_deleted=False)

    def inactive(self):
        return self.filter(Q(is_active=False) | Q(is_deleted=True))

    def not_deleted(self):
        return self.filter(is_deleted=False)

    def deleted(self):
        return self.filter(is_deleted=True)


class UserProfileManager(models.Manager):
    def get_queryset(self):
        return UserProfileQuerySet(self.model, using=self._db).not_deleted()


class UserProfile(models.Model):
    """
    Domain-specific user profile extensions.
    One-to-one relation with User model.
    """
    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
        primary_key=True
    )
    employee_id = models.CharField(
        _("Employee ID"),
        max_length=10,
        unique=True,
        editable=False,
        help_text=_("Unique auto-generated employee code (e.g., PT001)"),
    )
    phone = models.CharField(
        _("Phone Number"),
        max_length=15,
        validators=[RegexValidator(regex=r'^\+?1?\d{9,15}$',
                                   message=_("Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."))],
        blank=True,
        null=True,
        help_text=_("Primary contact phone number including country code"),
    )
    avatar = models.ImageField(
        _("Avatar"),
        upload_to=avatar_upload_to,
        validators=[
            FileExtensionValidator(allowed_extensions=["jpg", "jpeg", "png"]),
            validate_file_size
        ],
        blank=True,
        null=True,
        help_text=_("Profile image; max size 5MB (jpg/jpeg/png)")
    )
    roles = models.ManyToManyField(
        Role,
        related_name="users",
        blank=False,
        help_text=_("User can have multiple roles for flexible RBAC"),
    )
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="created_users",
        null=True,
        blank=True,
        help_text=_("User who created this profile")
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    is_deleted = models.BooleanField(default=False, help_text=_("Soft deletion flag"))

    # For forced password reset on first login or admin reset
    force_password_reset = models.BooleanField(default=True)

    objects = UserProfileManager()
    all_objects = models.Manager()  # Include deleted profiles if needed

    class Meta:
        verbose_name = _("UserProfile")
        verbose_name_plural = _("UserProfiles")
        ordering = ["employee_id"]

    def __str__(self):
        return f"{self.employee_id} - {self.user.get_full_name() or self.user.username}"

    def clean(self):
        if self.phone:
            # Basic phone normalization example - could be expanded
            self.phone = re.sub(r'\s+', '', self.phone)
        super().clean()

    def generate_employee_id(self):
        """
        Generates the next Employee ID in the format PT001, PT002, ...
        This should be called only once upon profile creation.
        """
        prefix = "PT"
        last_profile = UserProfile.all_objects.order_by("-employee_id").first()
        if last_profile and last_profile.employee_id.startswith(prefix):
            last_number = int(last_profile.employee_id[len(prefix):])
            new_number = last_number + 1
        else:
            new_number = 1
        return f"{prefix}{new_number:03d}"

    def save(self, *args, **kwargs):
        if not self.employee_id:
            self.employee_id = self.generate_employee_id()
        super().save(*args, **kwargs)

    def soft_delete(self):
        if not self.is_deleted:
            with transaction.atomic():
                self.is_deleted = True
                self.is_active = False
                self.save(update_fields=["is_deleted", "is_active", "updated_at"])
                # Log audit event
                AuditLog.log_action(
                    user=self.user,
                    target=self,
                    action_type=AuditLog.ActionType.SOFT_DELETE,
                    description="UserProfile soft deleted"
                )

    def restore(self):
        if self.is_deleted:
            with transaction.atomic():
                self.is_deleted = False
                self.is_active = True
                self.save(update_fields=["is_deleted", "is_active", "updated_at"])
                AuditLog.log_action(
                    user=self.user,
                    target=self,
                    action_type=AuditLog.ActionType.RESTORE,
                    description="UserProfile restored"
                )

    def has_role(self, role_name: str) -> bool:
        return self.roles.filter(name=role_name).exists()

    def role_names(self):
        return list(self.roles.values_list("name", flat=True))

    @property
    def is_owner(self):
        return self.has_role(Role.RoleName.OWNER)

    @property
    def is_manager(self):
        return self.has_role(Role.RoleName.MANAGER)

    @property
    def is_accountant(self):
        return self.has_role(Role.RoleName.ACCOUNTANT)

    @property
    def is_rto_staff(self):
        return self.has_role(Role.RoleName.RTO_STAFF)

    @property
    def is_data_entry(self):
        return self.has_role(Role.RoleName.DATA_ENTRY)


class OTPManager(models.Manager):
    def create_otp(self, user, otp_code, purpose, expires_in_minutes=None):
        if expires_in_minutes is None:
            expires_in_minutes = settings.OTP_EXPIRY_MINUTES
        expires_at = timezone.now() + timedelta(minutes=expires_in_minutes)
        otp_instance = self.create(user=user, otp_code=otp_code, purpose=purpose, expires_at=expires_at)
        return otp_instance


class OTP(models.Model):
    """
    OTP class to handle one-time passwords for critical operations.
    """
    PURPOSE_CHOICES = (
        ("password_reset", _("Password Reset")),
        ("login_otp", _("Login OTP")),
        ("2fa", _("Two Factor Authentication")),
    )

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="otps")
    otp_code = models.CharField(max_length=10)
    purpose = models.CharField(max_length=32, choices=PURPOSE_CHOICES)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    is_used = models.BooleanField(default=False)

    objects = OTPManager()

    class Meta:
        verbose_name = _("OTP")
        verbose_name_plural = _("OTPs")
        indexes = [
            models.Index(fields=["user", "otp_code", "purpose", "is_used", "expires_at"]),
        ]

    def clean(self):
        if self.expires_at < timezone.now():
            raise ValidationError(_("OTP cannot be expired at creation."))

    def mark_used(self):
        self.is_used = True
        self.save(update_fields=["is_used"])

    def is_valid(self):
        return (not self.is_used) and (self.expires_at > timezone.now())

    def __str__(self):
        return f"OTP ({self.purpose}) for {self.user}"


class DeletionRequest(models.Model):
    """
    Requests for soft deletion changes that require Owner approval.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    requester = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="deletion_requests_made")
    target_user_profile = models.ForeignKey(
        UserProfile,
        on_delete=models.CASCADE,
        related_name="deletion_requests_received",
        help_text=_("UserProfile targeted for deletion request"),
    )
    reason = models.TextField(help_text=_("Reason for deletion request"))
    created_at = models.DateTimeField(auto_now_add=True)
    is_approved = models.BooleanField(default=False)
    approved_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name="deletion_requests_approved",
        null=True,
        blank=True,
    )
    approved_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _("Deletion Request")
        verbose_name_plural = _("Deletion Requests")
        ordering = ["-created_at"]

    def approve(self, approver):
        if not self.is_approved:
            self.is_approved = True
            self.approved_by = approver
            self.approved_at = timezone.now()
            self.save(update_fields=["is_approved", "approved_by", "approved_at"])

            # Perform the soft deletion on the target profile
            self.target_user_profile.soft_delete()