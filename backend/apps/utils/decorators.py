import ipaddress
from django.http import HttpResponseForbidden
from django.views.decorators.cache import never_cache
from config.settings.base import ALLOWED_HEALTH_IPS

# ======== Middleware-like decorator to restrict by IP ========
def restrict_health_check(view_func):
    @never_cache
    def wrapper(request, *args, **kwargs):
        remote_ip = request.META.get("REMOTE_ADDR")
        try:
            ip = ipaddress.ip_address(remote_ip)
        except ValueError:
            return HttpResponseForbidden("Invalid IP")
        
        for allowed in ALLOWED_HEALTH_IPS:
            if "/" in allowed:
                if ip in ipaddress.ip_network(allowed):
                    return view_func(request, *args, **kwargs)
            elif remote_ip == allowed:
                return view_func(request, *args, **kwargs)
        
        return HttpResponseForbidden("Access Denied")
    
    return wrapper