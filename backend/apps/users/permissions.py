# backend/apps/users/permissions.py

from rest_framework import permissions
from apps.users.models import Role


class IsOwner(permissions.BasePermission):
    """
    Allows access only to users with the Owner role.
    Owner: Full system control including user management and deletion approvals.
    """

    def has_permission(self, request, view):
        profile = getattr(request.user, "profile", None)
        return bool(profile and profile.has_role(Role.RoleName.OWNER))


class IsManager(permissions.BasePermission):
    """
    Allows access to users with the Manager role.
    Manager: Full view/edit access excluding user management and deletion.
    """

    def has_permission(self, request, view):
        profile = getattr(request.user, "profile", None)
        return bool(profile and profile.has_role(Role.RoleName.MANAGER))


class IsAccountant(permissions.BasePermission):
    """
    Allows access to users with Accountant role.
    Accountant: Access to Salary, Challans, Drivers; can inactivate records and request deletions.
    """

    def has_permission(self, request, view):
        profile = getattr(request.user, "profile", None)
        return bool(profile and profile.has_role(Role.RoleName.ACCOUNTANT))


class IsRTOStaff(permissions.BasePermission):
    """
    Allows access to users with RTO Staff role.
    RTO Staff: Manages Vehicle & Document modules; can view audit logs, inactivate records, request deletion.
    """

    def has_permission(self, request, view):
        profile = getattr(request.user, "profile", None)
        return bool(profile and profile.has_role(Role.RoleName.RTO_STAFF))


class IsDataEntry(permissions.BasePermission):
    """
    Allows access exclusively for Data Entry role users.
    Data Entry: Limited visibility; can add/inactivate data in assigned modules only; no delete permissions.
    """

    def has_permission(self, request, view):
        profile = getattr(request.user, "profile", None)
        return bool(profile and profile.has_role(Role.RoleName.DATA_ENTRY))


class RoleBasedPermission(permissions.BasePermission):
    """
    Complex, module-scoped Role-Based Access Control:
    Enforces:
    - Role hierarchy (Owner > Manager > others)
    - Scoped permissions per role and module
    - Fine-grained read/write/delete/inactivate rights
    This class should be extended or configured per view/module.
    """

    # Define permission scopes per role as class attributes or via init
    role_permissions = {
        Role.RoleName.OWNER: {
            "can_manage_users": True,
            "can_delete": True,
            "can_inactivate": True,
            "can_view_all": True,
            "can_request_deletion": True,
        },
        Role.RoleName.MANAGER: {
            "can_manage_users": False,
            "can_delete": False,
            "can_inactivate": True,
            "can_view_all": True,
            "can_request_deletion": False,
        },
        Role.RoleName.ACCOUNTANT: {
            "can_manage_users": False,
            "can_delete": False,
            "can_inactivate": True,
            "can_view_all": False,
            "can_request_deletion": True,
            "modules": {"salary", "challans", "drivers"},
        },
        Role.RoleName.RTO_STAFF: {
            "can_manage_users": False,
            "can_delete": False,
            "can_inactivate": True,
            "can_view_all": False,
            "can_request_deletion": True,
            "modules": {"vehicles", "documents"},
        },
        Role.RoleName.DATA_ENTRY: {
            "can_manage_users": False,
            "can_delete": False,
            "can_inactivate": False,
            "can_view_all": False,
            "can_request_deletion": False,
            "modules": {"assigned_data_entry_modules"},
        },
    }

    def has_permission(self, request, view):
        """
        Grants or denies permission based on user's roles and view's required access.
        Expect the view to have attributes like `required_module` (str) and `required_action` (str e.g., 'view', 'edit', 'delete', 'inactivate').
        """
        user = request.user
        if not user or not user.is_authenticated:
            return False

        profile = getattr(user, "profile", None)
        if not profile or profile.is_deleted or not profile.is_active:
            return False

        required_module = getattr(view, "required_module", None)
        required_action = getattr(view, "required_action", None)  # e.g., 'view', 'edit', 'delete', 'inactivate'

        # Owners have unrestricted access
        if profile.has_role(Role.RoleName.OWNER):
            return True

        user_roles = profile.role_names()

        # Aggregate permissions from all user roles, most permissive wins
        can_manage_users = False
        can_delete = False
        can_inactivate = False
        can_view_all = False
        can_request_deletion = False
        allowed_modules = set()

        for role in user_roles:
            perms = self.role_permissions.get(role, {})
            if perms.get("can_manage_users", False):
                can_manage_users = True
            if perms.get("can_delete", False):
                can_delete = True
            if perms.get("can_inactivate", False):
                can_inactivate = True
            if perms.get("can_view_all", False):
                can_view_all = True
            if perms.get("can_request_deletion", False):
                can_request_deletion = True
            allowed_modules.update(perms.get("modules", []))

        # Check module scope
        if required_module:
            if not can_view_all and (required_module not in allowed_modules):
                return False

        # Check action permissions
        if required_action == "delete" and not can_delete:
            return False
        if required_action == "inactivate" and not can_inactivate:
            return False
        if required_action == "manage_users" and not can_manage_users:
            return False
        if required_action == "request_deletion" and not can_request_deletion:
            return False

        # Default allow read/view if module permitted or can_view_all
        if required_action in ("view", None):
            return True

        # Default deny
        return False


class ReadOnly(permissions.BasePermission):
    """
    Allows read-only access only.
    """

    def has_permission(self, request, view):
        return request.method in permissions.SAFE_METHODS


class IsAuthenticatedAndActive(permissions.BasePermission):
    """
    Allows access only to authenticated users with active (not soft deleted) profiles.
    """

    def has_permission(self, request, view):
        user = request.user
        if not user or not user.is_authenticated:
            return False

        profile = getattr(user, "profile", None)
        if not profile:
            return False

        if not profile.is_active or profile.is_deleted:
            return False

        return True