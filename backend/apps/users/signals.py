# backend/apps/users/signals.py

import logging
from django.db.models.signals import post_save, post_delete, pre_save
from django.contrib.auth.models import update_last_login
from django.dispatch import receiver
from django.utils.timezone import now
from django.contrib.auth import get_user_model
from django.core.exceptions import ObjectDoesNotExist
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken

from apps.audit.models import AuditLog
from apps.users.models import UserProfile, DeletionRequest


logger = logging.getLogger("django")
User = get_user_model()


@receiver(post_save, sender=User)
def create_or_update_user_profile(sender, instance, created, **kwargs):
    """
    Automatically create or update UserProfile when User is created or updated.
    """
    if created:
        UserProfile.objects.create(user=instance)
        logger.info(f"Created UserProfile for new user {instance.username} (ID: {instance.id})")
        AuditLog.log_action(
            user=instance,
            target=instance,
            action_type=AuditLog.ActionType.CREATE,
            description="User created and profile initialized"
        )
    else:
        try:
            profile = instance.profile
            profile.save(update_fields=["updated_at"])
        except ObjectDoesNotExist:
            UserProfile.objects.create(user=instance)
            logger.warning(f"UserProfile missing for user {instance.username}. Created automatically.")
        AuditLog.log_action(
            user=instance,
            target=instance,
            action_type=AuditLog.ActionType.UPDATE,
            description="User updated"
        )


@receiver(pre_save, sender=UserProfile)
def enforce_force_password_reset(sender, instance, **kwargs):
    """
    Ensure force_password_reset flag is True on creation and on admin-triggered resets.
    """
    if not instance.pk:
        # New UserProfile, ensure force_password_reset is True initially
        instance.force_password_reset = True
    else:
        old_instance = UserProfile.objects.filter(pk=instance.pk).first()
        if old_instance and old_instance.force_password_reset != instance.force_password_reset:
            # Log password reset forced event
            if instance.force_password_reset:
                AuditLog.log_action(
                    user=instance.user,
                    target=instance,
                    action_type=AuditLog.ActionType.FLAG_SET,
                    description="Force password reset flag set by admin"
                )


@receiver(post_save, sender=DeletionRequest)
def handle_deletion_request_created(sender, instance, created, **kwargs):
    """
    On new deletion request creation, log audit and notify Owners asynchronously.
    """
    if created:
        AuditLog.log_action(
            user=instance.requester,
            target=instance.target_user_profile.user,
            action_type=AuditLog.ActionType.DELETION_REQUEST,
            description=f"Deletion requested: {instance.reason}"
        )
        try:
            from apps.notifications.tasks import notify_owner_deletion_request
            notify_owner_deletion_request.delay(instance.id)
        except ImportError:
            logger.warning("Notification task 'notify_owner_deletion_request' not available")


@receiver(post_save, sender=User)
def log_user_login(sender, instance, **kwargs):
    """
    Hook to log user login? Usually handled via middleware or authentication backend.
    Alternatively, call update_last_login signal here.
    """
    # Example: Update last login timestamp on login
    update_last_login(sender, instance, **kwargs)


@receiver(post_delete, sender=UserProfile)
def audit_userprofile_deleted(sender, instance, **kwargs):
    """
    If UserProfile deletion occurs (should be rare due to soft delete), audit it.
    """
    AuditLog.log_action(
        user=instance.user,
        target=instance,
        action_type=AuditLog.ActionType.DELETE,
        description="UserProfile deleted"
    )


@receiver(post_save, sender=UserProfile)
def audit_userprofile_save(sender, instance, created, **kwargs):
    """
    Audit creation or update of UserProfile
    """
    action = AuditLog.ActionType.CREATE if created else AuditLog.ActionType.UPDATE
    AuditLog.log_action(
        user=instance.user,
        target=instance,
        action_type=action,
        description="UserProfile created" if created else "UserProfile updated"
    )