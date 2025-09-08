from django.contrib import admin
from django.urls import path, include
from django.http import HttpResponse
from health_check.views import MainView
from apps.utils.decorators import restrict_health_check

# ======== Home View ========
def home_view(request):
    """Simple home page for backend API root."""
    return HttpResponse("Welcome to the Purshottam Fleet ERP backend!")

# ======== URL Patterns ========
urlpatterns = [
    path('', home_view, name='home'),
    path('admin/', admin.site.urls),
    path('health/', restrict_health_check(MainView.as_view()), name='health_check'),
    path('api/users/', include('apps.users.urls')),
]