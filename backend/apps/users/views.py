# backend/apps/users/views.py

from django.contrib.auth import login, logout, get_user_model
from django.db import transaction
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from rest_framework import status, generics, permissions, views, viewsets, mixins
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenRefreshView

from apps.users.models import UserProfile, OTP, Role, DeletionRequest
from apps.users.serializers import (
    UserRegisterSerializer,
    UserLoginSerializer,
    UserSerializer,
    ChangePasswordSerializer,
    OTPRequestSerializer,
    OTPVerifySerializer,
    UserProfileUpdateSerializer,
    DeletionRequestSerializer,
    UserRoleAssignSerializer,
)
from apps.users.permissions import (
    IsOwner,
    IsManager,
    IsAccountant,
    IsRTOStaff,
    IsDataEntry,
    RoleBasedPermission,
)
from apps.notifications.tasks import send_otp_sms, send_otp_email, notify_owner_deletion_request


User = get_user_model()


class UserRegisterView(generics.CreateAPIView):
    """
    User registration endpoint.
    Allows creation of new user + profile with initial default role assignment.
    """
    serializer_class = UserRegisterSerializer
    permission_classes = [permissions.AllowAny]

    @transaction.atomic
    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        return Response({"detail": _("Registration successful.")}, status=status.HTTP_201_CREATED)


class UserLoginView(views.APIView):
    """
    User login with username and password, returning JWT tokens.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]

        # Enforce forced password reset if required before allowing login to full system
        if user.profile.force_password_reset:
            return Response(
                {"detail": _("Password reset required. Please change your password.")},
                status=status.HTTP_403_FORBIDDEN,
            )

        login(request, user)
        # Return token pair
        return Response(
            {
                "refresh": serializer.validated_data["refresh"],
                "access": serializer.validated_data["access"],
                "user": UserSerializer(user).data,
            }
        )


class LogoutView(views.APIView):
    """
    Blacklist the refresh token on logout.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response(
                {"detail": _("Refresh token required.")},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except Exception:
            return Response(
                {"detail": _("Invalid or expired token.")},
                status=status.HTTP_400_BAD_REQUEST,
            )
        logout(request)
        return Response({"detail": _("Logout successful.")}, status=status.HTTP_204_NO_CONTENT)


class TokenRefreshViewCustom(TokenRefreshView):
    """
    Extend default JWT token refresh view if customization needed.
    """
    pass


class ChangePasswordView(generics.UpdateAPIView):
    """
    Authenticated user can change password here.
    """
    serializer_class = ChangePasswordSerializer
    model = User
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self, queryset=None):
        return self.request.user

    @transaction.atomic
    def update(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response({"detail": _("Password changed successfully.")}, status=status.HTTP_200_OK)


class UserProfileView(generics.RetrieveUpdateAPIView):
    """
    Retrieve or update profile info (phone, avatar).
    """
    serializer_class = UserProfileUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user.profile


class OTPRequestView(views.APIView):
    """
    Request OTP for password reset or 2FA via SMS or Email asynchronously.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = OTPRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        phone = serializer.validated_data.get("phone")
        email = serializer.validated_data.get("email")
        user = None
        # Identify user by phone or email
        if phone:
            try:
                user_profile = UserProfile.objects.get(phone=phone, is_deleted=False, is_active=True)
                user = user_profile.user
            except UserProfile.DoesNotExist:
                pass
        if not user and email:
            try:
                user = User.objects.get(email=email, is_active=True)
            except User.DoesNotExist:
                pass

        if not user:
            return Response({"detail": _("User not found.")}, status=status.HTTP_404_NOT_FOUND)

        # Generate OTP
        from apps.users.utils import generate_otp_code  # Utility to generate OTP code

        otp_code = generate_otp_code()
        otp_obj = OTP.objects.create_otp(user=user, otp_code=otp_code, purpose="password_reset")

        # Send via SMS and/or Email asynchronously
        if phone:
            send_otp_sms.delay(phone, otp_code)
        if email:
            send_otp_email.delay(email, otp_code)

        return Response({"detail": _("OTP sent successfully.")})


class OTPVerifyView(views.APIView):
    """
    Verify OTP for password resets or multi-factor authentication.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = OTPVerifySerializer(data=request.data, context={"request": request})
        serializer.is_valid(raise_exception=True)

        # OTP is valid
        user = serializer.save()
        return Response({"detail": _("OTP verification successful."), "user_id": user.id})


class UserViewSet(viewsets.ModelViewSet):
    """
    Full CRUD for User with role management and soft deletion workflow.
    Permissions enforced strictly by custom RoleBasedPermission.
    """
    serializer_class = UserSerializer
    queryset = User.objects.all().select_related("profile").prefetch_related("profile__roles")
    permission_classes = [permissions.IsAuthenticated, RoleBasedPermission]

    def get_queryset(self):
        qs = super().get_queryset()
        # Owners and managers see all including inactive; others see active only
        user_profile = getattr(self.request.user, "profile", None)
        if user_profile and user_profile.is_owner:
            return qs
        if user_profile and user_profile.is_manager:
            return qs.filter(profile__is_deleted=False)
        # Other roles see only active, non-deleted users
        return qs.filter(is_active=True, profile__is_deleted=False)

    def perform_destroy(self, instance):
        # Deletion only requested via soft delete request system
        raise PermissionError(_("Use soft deletion request API to delete users."))

    @action(detail=True, methods=["post"], permission_classes=[IsOwner])
    def soft_delete(self, request, pk=None):
        """
        Owners can perform soft delete directly.
        """
        user = self.get_object()
        if user.profile.is_deleted:
            return Response({"detail": _("User already deleted.")}, status=status.HTTP_400_BAD_REQUEST)
        user.profile.soft_delete()
        return Response({"detail": _("User soft deleted.")})

    @action(detail=True, methods=["post"], permission_classes=[IsOwner])
    def restore(self, request, pk=None):
        """
        Owners can restore soft-deleted user.
        """
        user = self.get_object()
        if not user.profile.is_deleted:
            return Response({"detail": _("User is not deleted.")}, status=status.HTTP_400_BAD_REQUEST)
        user.profile.restore()
        return Response({"detail": _("User restored.")})

    @action(detail=True, methods=["post"], permission_classes=[IsOwner])
    def assign_roles(self, request, pk=None):
        """
        Assign roles to user; expects roles[ids].
        """
        user = self.get_object()
        serializer = UserRoleAssignSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.update(user, serializer.validated_data)
        return Response({"detail": _("Roles updated.")}, status=status.HTTP_200_OK)


class DeletionRequestViewSet(viewsets.ModelViewSet):
    """
    Handles creation, approval, and viewing of deletion requests.
    Only Owners can approve deletion requests.
    """
    serializer_class = DeletionRequestSerializer
    queryset = DeletionRequest.objects.all()
    permission_classes = [permissions.IsAuthenticated, RoleBasedPermission]

    def get_queryset(self):
        user_profile = getattr(self.request.user, "profile", None)
        if user_profile and user_profile.is_owner:
            return super().get_queryset()
        # Other roles see their own requests only
        return super().get_queryset().filter(requester=self.request.user)

    def perform_create(self, serializer):
        serializer.save(requester=self.request.user)
        # Notify Owners asynchronously
        notify_owner_deletion_request.delay(serializer.instance.id)

    @action(detail=True, methods=["post"], permission_classes=[IsOwner])
    def approve(self, request, pk=None):
        deletion_request = self.get_object()
        if deletion_request.is_approved:
            return Response({"detail": _("Deletion request already approved.")}, status=status.HTTP_400_BAD_REQUEST)
        deletion_request.approve(approver=request.user)
        return Response({"detail": _("Deletion request approved and user soft deleted.")}, status=status.HTTP_200_OK)