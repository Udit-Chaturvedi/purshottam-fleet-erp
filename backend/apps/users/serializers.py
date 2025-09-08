# backend/apps/users/serializers.py

from django.contrib.auth import authenticate, password_validation
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.files.images import get_image_dimensions
from django.utils import timezone

from apps.users.models import User, UserProfile, Role, OTP, DeletionRequest


class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ["id", "name", "description"]


class UserProfileSerializer(serializers.ModelSerializer):
    roles = RoleSerializer(many=True, read_only=True)
    avatar = serializers.ImageField(
        max_length=None,
        allow_empty_file=True,
        use_url=True,
        required=False,
        help_text=_("User avatar image. Max size 5MB, JPEG/PNG formats."),
    )

    class Meta:
        model = UserProfile
        fields = [
            "employee_id",
            "phone",
            "avatar",
            "roles",
            "created_by",
            "is_active",
            "is_deleted",
            "force_password_reset",
            "created_at",
            "updated_at",
        ]
        read_only_fields = [
            "employee_id",
            "created_by",
            "is_active",
            "is_deleted",
            "created_at",
            "updated_at",
            "roles",
        ]

    def validate_avatar(self, value):
        # Validate image dimensions and size (max 5MB)
        max_size_mb = 5
        max_width = 1024
        max_height = 1024
        if value.size > max_size_mb * 1024 * 1024:
            raise serializers.ValidationError(f"Avatar size should not exceed {max_size_mb}MB.")
        width, height = get_image_dimensions(value)
        if width > max_width or height > max_height:
            raise serializers.ValidationError(
                f"Avatar dimensions should not exceed {max_width}x{max_height}px."
            )
        return value


class UserSerializer(serializers.ModelSerializer):
    profile = UserProfileSerializer(read_only=True)
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True, allow_blank=False)
    last_name = serializers.CharField(required=False, allow_blank=True)
    is_active = serializers.BooleanField(read_only=True)

    class Meta:
        model = User
        fields = [
            "id",
            "uuid",
            "username",
            "email",
            "first_name",
            "last_name",
            "is_active",
            "profile",
        ]
        read_only_fields = ["id", "uuid", "username", "is_active"]

    def update(self, instance, validated_data):
        # Update user fields and profile if relevant fields exist.
        profile_data = self.context.get("profile_data", {})
        for attr, value in validated_data.items():
            if attr != "profile":
                setattr(instance, attr, value)
        instance.save()

        if profile_data:
            profile_serializer = UserProfileSerializer(
                instance=instance.profile, data=profile_data, partial=True
            )
            profile_serializer.is_valid(raise_exception=True)
            profile_serializer.save()

        return instance


class UserRegisterSerializer(serializers.Serializer):
    username = serializers.CharField(
        required=True,
        min_length=3,
        max_length=150,
        help_text=_("Unique username, 3-150 characters."),
    )
    email = serializers.EmailField(required=True)
    first_name = serializers.CharField(required=True)
    last_name = serializers.CharField(required=False, allow_blank=True)
    password = serializers.CharField(
        write_only=True,
        required=True,
        min_length=12,
        style={"input_type": "password"},
        help_text=_("Password must be at least 12 characters long."),
    )
    phone = serializers.CharField(required=False, allow_blank=True)

    def validate_username(self, value):
        if User.objects.filter(username__iexact=value).exists():
            raise serializers.ValidationError(_("Username is already taken."))
        return value

    def validate_password(self, value):
        password_validation.validate_password(value)
        return value

    def create(self, validated_data):
        phone = validated_data.pop("phone", None)
        password = validated_data.pop("password")
        user = User.objects.create(
            username=validated_data["username"],
            email=validated_data["email"],
            first_name=validated_data["first_name"],
            last_name=validated_data.get("last_name", ""),
            is_active=True,
        )
        user.set_password(password)
        user.save()

        profile = UserProfile.objects.create(
            user=user,
            phone=phone,
            created_by=self.context.get("request").user
            if self.context.get("request", None)
            else None,
            force_password_reset=True,
        )
        # Optionally assign default role Data Entry or others according to business logic
        default_role = Role.objects.filter(name=Role.RoleName.DATA_ENTRY).first()
        if default_role:
            profile.roles.add(default_role)

        return user


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})
    access = serializers.CharField(read_only=True)
    refresh = serializers.CharField(read_only=True)

    def validate(self, attrs):
        username = attrs.get("username")
        password = attrs.get("password")

        if username and password:
            user = authenticate(username=username, password=password)
            if not user:
                raise serializers.ValidationError(_("Invalid username/password."))
            if not user.is_active or (hasattr(user, "profile") and user.profile.is_deleted):
                raise serializers.ValidationError(_("User account is inactive or deleted."))

            # Token generation with SimpleJWT
            refresh = RefreshToken.for_user(user)
            attrs["user"] = user
            attrs["access"] = str(refresh.access_token)
            attrs["refresh"] = str(refresh)
            return attrs
        else:
            raise serializers.ValidationError(_("Must include username and password."))


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True, required=True, style={"input_type": "password"})
    new_password = serializers.CharField(
        write_only=True, required=True, style={"input_type": "password"}, min_length=12
    )

    def validate_new_password(self, value):
        password_validation.validate_password(value)
        return value

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError(_("Old password is incorrect."))
        return value

    def save(self, **kwargs):
        user = self.context["request"].user
        user.set_password(self.validated_data["new_password"])
        # Reset force_password_reset flag on profile
        user.profile.force_password_reset = False
        user.profile.save(update_fields=["force_password_reset"])
        user.save()
        return user


class OTPRequestSerializer(serializers.Serializer):
    phone = serializers.CharField(required=False, allow_blank=True)
    email = serializers.EmailField(required=False)

    def validate(self, data):
        if not data.get("phone") and not data.get("email"):
            raise serializers.ValidationError(_("Either phone or email must be provided."))
        return data


class OTPVerifySerializer(serializers.Serializer):
    otp_code = serializers.CharField(required=True, max_length=10)
    purpose = serializers.ChoiceField(choices=OTP.PURPOSE_CHOICES, required=True)

    def validate(self, attrs):
        user = self.context["request"].user
        otp_code = attrs.get("otp_code")
        purpose = attrs.get("purpose")
        try:
            otp_obj = OTP.objects.filter(
                user=user,
                otp_code=otp_code,
                purpose=purpose,
                is_used=False,
                expires_at__gt=timezone.now(),
            ).latest("created_at")
        except OTP.DoesNotExist:
            raise serializers.ValidationError(_("Invalid or expired OTP."))
        attrs["otp_obj"] = otp_obj
        return attrs

    def save(self, **kwargs):
        otp_obj = self.validated_data["otp_obj"]
        otp_obj.mark_used()
        return otp_obj.user


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    avatar = serializers.ImageField(required=False, allow_null=True)

    class Meta:
        model = UserProfile
        fields = ["phone", "avatar"]

    def validate_avatar(self, value):
        max_size_mb = 5
        max_width = 1024
        max_height = 1024
        if value.size > max_size_mb * 1024 * 1024:
            raise serializers.ValidationError(f"Avatar size should not exceed {max_size_mb}MB.")
        width, height = get_image_dimensions(value)
        if width > max_width or height > max_height:
            raise serializers.ValidationError(
                f"Avatar dimensions should not exceed {max_width}x{max_height}px."
            )
        return value


class DeletionRequestSerializer(serializers.ModelSerializer):
    requester = serializers.StringRelatedField(read_only=True)
    approved_by = serializers.StringRelatedField(read_only=True)
    target_user_profile = serializers.PrimaryKeyRelatedField(queryset=UserProfile.objects.all())

    class Meta:
        model = DeletionRequest
        fields = [
            "id",
            "requester",
            "target_user_profile",
            "reason",
            "created_at",
            "is_approved",
            "approved_by",
            "approved_at",
        ]
        read_only_fields = [
            "id",
            "requester",
            "created_at",
            "is_approved",
            "approved_by",
            "approved_at",
        ]

    def create(self, validated_data):
        request = self.context["request"]
        validated_data["requester"] = request.user
        return super().create(validated_data)


class MinimalUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name"]


class UserAuditLogSerializer(serializers.Serializer):
    # For audit log integration if needed
    id = serializers.UUIDField()
    user = MinimalUserSerializer()
    action_type = serializers.CharField()
    target_repr = serializers.CharField()
    timestamp = serializers.DateTimeField()
    ip_address = serializers.CharField()
    user_agent = serializers.CharField()
    description = serializers.CharField()


# Additional serializers for role assignment/updation if needed
class UserRoleAssignSerializer(serializers.Serializer):
    roles = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all(), many=True)

    def update(self, instance, validated_data):
        profile = instance.profile
        roles = validated_data.get("roles")
        if roles:
            profile.roles.set(roles)
            profile.save(update_fields=["updated_at"])
        return instance