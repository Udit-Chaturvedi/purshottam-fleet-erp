# backend/apps/audit/models.py

import uuid
from django.conf import settings
from django.db import models
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.utils.translation import gettext_lazy as _
from django.utils.timezone import now


class AuditLog(models.Model):
    """
    This model captures immutable audit trail entries across the ERP system.

    Each entry logs key user actions for compliance, traceability, and rollback.
    Related to a user (actor), target object, action type, and client metadata.
    """

    class ActionType(models.TextChoices):
        CREATE = "create", _("Create")
        UPDATE = "update", _("Update")
        DELETE = "delete", _("Delete")
        SOFT_DELETE = "soft_delete", _("Soft Delete")
        RESTORE = "restore", _("Restore")
        LOGIN = "login", _("Login")
        LOGOUT = "logout", _("Logout")
        INACTIVATE = "inactivate", _("Inactivate")
        REACTIVATE = "reactivate", _("Reactivate")
        DELETION_REQUEST = "deletion_request", _("Deletion Request")
        FLAG_SET = "flag_set", _("Flag Set")
        OTHER = "other", _("Other")

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(default=now, db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_logs",
        help_text=_("User who performed the action"),
    )
    action_type = models.CharField(
        max_length=20,
        choices=ActionType.choices,
        default=ActionType.OTHER,
        db_index=True,
    )
    target_content_type = models.ForeignKey(
        "contenttypes.ContentType",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        help_text=_("Content type of the audited object"),
    )
    target_object_id = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text=_("Primary key of the audited object as string"),
    )
    target = GenericForeignKey("target_content_type", "target_object_id")
    description = models.TextField(blank=True, help_text=_("Description of the action"))
    ip_address = models.GenericIPAddressField(
        _("IP Address"), null=True, blank=True, help_text=_("Client IP address")
    )
    user_agent = models.TextField(
        _("User Agent"), null=True, blank=True, help_text=_("User agent string")
    )

    class Meta:
        verbose_name = _("Audit Log")
        verbose_name_plural = _("Audit Logs")
        ordering = ("-timestamp",)
        indexes = [
            models.Index(fields=["user"]),
            models.Index(fields=["action_type"]),
            models.Index(fields=["target_content_type", "target_object_id"]),
        ]

    def __str__(self):
        return f"[{self.timestamp}] {self.action_type} by {self.user} on {self.target_repr()}"

    def target_repr(self):
        try:
            return f"{self.target_content_type} #{self.target_object_id}"
        except Exception:
            return "Unknown"

    @classmethod
    def log_action(cls, user, target, action_type, description="", ip_address=None, user_agent=None):
        """
        Classmethod utility to create an audit log entry.

        Args:
            user: User instance performing the action.
            target: Target model instance affected.
            action_type: One of ActionType values.
            description: Optional descriptive text.
            ip_address: Optional client IP.
            user_agent: Optional user agent string.
        """
        from django.contrib.contenttypes.models import ContentType

        content_type = ContentType.objects.get_for_model(target) if target else None
        target_pk = str(target.pk) if target else None

        log_entry = cls.objects.create(
            user=user,
            action_type=action_type,
            target_content_type=content_type,
            target_object_id=target_pk,
            description=description,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return log_entry
