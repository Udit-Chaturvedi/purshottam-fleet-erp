# backend/apps/users/utils.py

import random
import string
from datetime import datetime
from django.utils import timezone
from django.core.exceptions import ValidationError
from apps.audit.models import AuditLog
from apps.users.models import UserProfile, OTP


def generate_employee_id():
    """
    Generate next unique Employee ID in format PT001, PT002, ...
    Note: Use atomic DB locks if highly concurrent employee creation expected.
    """
    prefix = "PT"
    last_profile = UserProfile.all_objects.order_by("-employee_id").first()
    if last_profile and last_profile.employee_id.startswith(prefix):
        last_number = int(last_profile.employee_id[len(prefix):])
        new_number = last_number + 1
    else:
        new_number = 1
    return f"{prefix}{new_number:03d}"


def generate_otp_code(length=6):
    """
    Generate a secure random numeric OTP code of specified length.
    """
    if length < 4 or length > 10:
        raise ValidationError("OTP length must be between 4 and 10 digits.")
    digits = string.digits
    # Use SystemRandom for cryptographically secure randomness
    secure_random = random.SystemRandom()
    return ''.join(secure_random.choice(digits) for _ in range(length))


def create_and_log_otp(user, purpose, length=None):
    """
    Create an OTP instance and log audit entry.
    """
    if length is None:
        length = 6
    otp_code = generate_otp_code(length)
    expires_at = timezone.now() + timezone.timedelta(minutes=15)  # Use 15 or configured expiry
    otp = OTP.objects.create(user=user, otp_code=otp_code, purpose=purpose, expires_at=expires_at)

    AuditLog.log_action(
        user=user,
        target=user,
        action_type=AuditLog.ActionType.CREATE,
        description=f"OTP {purpose} generated and sent",
    )

    return otp


def log_user_action(user, target, action_type, description, ip_address=None, user_agent=None):
    """
    Generic utility to log user actions into AuditLog with metadata.
    """
    AuditLog.log_action(
        user=user,
        target=target,
        action_type=action_type,
        description=description,
        ip_address=ip_address,
        user_agent=user_agent,
    )


def validate_phone_number(phone: str) -> bool:
    """
    Validates phone number format (+countrycode + digits, length 9-15).
    Raises ValidationError on invalid format.
    """
    import re
    pattern = re.compile(r"^\+?1?\d{9,15}$")
    if not pattern.match(phone):
        raise ValidationError(f"Phone number '{phone}' is not valid. Must be 9-15 digits with optional '+'.")


def normalize_phone_number(phone: str) -> str:
    """
    Normalize phone number by stripping whitespace and unnecessary characters.
    """
    if not phone:
        return ""
    return ''.join(filter(str.isdigit, phone.strip().replace("+", "")))


def soft_delete_instance(instance, user):
    """
    Utility method to perform soft deletion of any model instance with audit logging.
    The instance must have 'is_deleted' and 'is_active' boolean fields.
    """
    if hasattr(instance, "is_deleted") and hasattr(instance, "is_active"):
        if instance.is_deleted:
            return  # Already deleted
        instance.is_deleted = True
        instance.is_active = False
        instance.save(update_fields=["is_deleted", "is_active"])
        AuditLog.log_action(
            user=user,
            target=instance,
            action_type=AuditLog.ActionType.SOFT_DELETE,
            description=f"Soft deleted by {user}",
        )
    else:
        raise ValueError("Instance does not support soft deletion (missing fields).")


def restore_soft_deleted_instance(instance, user):
    """
    Utility to restore soft-deleted instance with audit logging.
    """
    if hasattr(instance, "is_deleted") and hasattr(instance, "is_active"):
        if not instance.is_deleted:
            return  # Not deleted
        instance.is_deleted = False
        instance.is_active = True
        instance.save(update_fields=["is_deleted", "is_active"])
        AuditLog.log_action(
            user=user,
            target=instance,
            action_type=AuditLog.ActionType.RESTORE,
            description=f"Restored by {user}",
        )
    else:
        raise ValueError("Instance does not support soft deletion (missing fields).")