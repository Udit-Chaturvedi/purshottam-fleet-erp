# backend/apps/notifications/tasks.py

import logging
from celery import shared_task
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
import requests

logger = logging.getLogger("django")


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_otp_sms(self, phone_number: str, otp_code: str) -> bool:
    """
    Sends OTP SMS via MSG91 API asynchronously with retry on failure.
    """
    try:
        msg91_api_key = settings.MSG91_AUTH_KEY
        sender_id = settings.MSG91_SENDER_ID
        otp_template_id = settings.MSG91_OTP_TEMPLATE_ID
        url = "https://api.msg91.com/api/v5/otp"

        payload = {
            "template_id": otp_template_id,
            "mobile": phone_number,
            "authkey": msg91_api_key,
            "otp": otp_code,
            "otp_length": len(otp_code),
            "otp_expiry": settings.OTP_EXPIRY_MINUTES,
        }
        headers = {"Content-Type": "application/json"}

        response = requests.post(url, json=payload, headers=headers, timeout=10)
        response.raise_for_status()
        result = response.json()

        if result.get("type") == "success":
            logger.info(f"OTP SMS sent successfully to {phone_number}")
            return True
        else:
            logger.error(f"Failed to send OTP SMS to {phone_number}: {result.get('message')}")
            raise Exception(f"MSG91 error: {result.get('message')}")

    except Exception as exc:
        logger.warning(f"Send OTP SMS failed for {phone_number}: {exc}, retrying...")
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=60)
def send_otp_email(self, email_address: str, otp_code: str) -> bool:
    """
    Sends OTP email asynchronously with retry on failure.
    Uses Django’s email backend.
    """
    subject = "Your OTP Code"
    try:
        message = render_to_string(
            "emails/otp_email.html",
            {
                "otp_code": otp_code,
                "expiry_minutes": settings.OTP_EXPIRY_MINUTES,
                "support_email": settings.DEFAULT_FROM_EMAIL,
            },
        )
        send_mail(
            subject=subject,
            message="",
            html_message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email_address],
            fail_silently=False,
        )
        logger.info(f"OTP Email sent successfully to {email_address}")
        return True
    except Exception as exc:
        logger.warning(f"Send OTP Email failed for {email_address}: {exc}, retrying...")
        raise self.retry(exc=exc)


@shared_task(bind=True, max_retries=3, default_retry_delay=300)
def notify_owner_deletion_request(self, deletion_request_id: str) -> None:
    """
    Send notification to Owner(s) when a user deletion request is created.
    Notification channels: Email + SMS (using MSG91).
    """
    from apps.users.models import DeletionRequest, UserProfile

    try:
        deletion_request = DeletionRequest.objects.select_related(
            "requester", "target_user_profile"
        ).get(pk=deletion_request_id)

        owners_emails = UserProfile.objects.filter(
            roles__name=UserProfile.objects.model.Role.RoleName.OWNER,
            is_active=True,
            is_deleted=False,
        ).values_list("user__email", flat=True).distinct()

        if not owners_emails:
            logger.warning("No owners found to notify for deletion request.")

        subject = "User Deletion Request Pending Approval"
        message_context = {
            "requester": deletion_request.requester.username,
            "target_employee_id": deletion_request.target_user_profile.employee_id,
            "target_username": deletion_request.target_user_profile.user.username,
            "reason": deletion_request.reason,
            "request_date": deletion_request.created_at,
            "support_email": settings.DEFAULT_FROM_EMAIL,
        }

        email_body = render_to_string("emails/deletion_request_notification.html", message_context)

        send_mail(
            subject=subject,
            message="",
            html_message=email_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=list(owners_emails),
            fail_silently=False,
        )

        owners_phones = UserProfile.objects.filter(
            roles__name=UserProfile.objects.model.Role.RoleName.OWNER,
            is_active=True,
            is_deleted=False,
        ).values_list("phone", flat=True).distinct()

        sms_text = (
            f"User deletion request: {deletion_request.requester.username} requested deletion "
            f"of user {deletion_request.target_user_profile.employee_id}. Reason: {deletion_request.reason[:100]}"
        )

        for phone in owners_phones:
            if phone:
                send_otp_sms.delay(phone, sms_text)

        logger.info(f"Notified owners of deletion request {deletion_request_id}")

    except DeletionRequest.DoesNotExist:
        logger.error(f"DeletionRequest with id {deletion_request_id} does not exist.")
    except Exception as exc:
        logger.error(f"Error notifying owners of deletion request {deletion_request_id}: {exc}")
        raise self.retry(exc=exc)
