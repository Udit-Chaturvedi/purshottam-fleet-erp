# backend/apps/users/urls.py

from django.urls import path, include
from rest_framework.routers import DefaultRouter

from apps.users import views

router = DefaultRouter()
router.register(r"users", views.UserViewSet, basename="user")
router.register(r"deletion-requests", views.DeletionRequestViewSet, basename="deletionrequest")

urlpatterns = [
    # Registration and Authentication
    path("register/", views.UserRegisterView.as_view(), name="user-register"),
    path("login/", views.UserLoginView.as_view(), name="user-login"),
    path("logout/", views.LogoutView.as_view(), name="user-logout"),
    path("token/refresh/", views.TokenRefreshViewCustom.as_view(), name="token-refresh"),
    path(
        "password/change/",
        views.ChangePasswordView.as_view(),
        name="password-change"
    ),

    # Profile
    path(
        "profile/",
        views.UserProfileView.as_view(),
        name="user-profile"
    ),

    # OTP Management
    path(
        "otp/request/",
        views.OTPRequestView.as_view(),
        name="otp-request"
    ),
    path(
        "otp/verify/",
        views.OTPVerifyView.as_view(),
        name="otp-verify"
    ),

    # Router-registered viewsets (users, deletion-requests)
    path("", include(router.urls)),
]