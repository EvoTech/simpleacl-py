# -*- mode: python; coding: utf-8; -*-
from __future__ import absolute_import, unicode_literals
from ..exceptions import MissingRole, MissingPrivilege, MissingResource
from ..paste import get_acl
from .utils import get_role_name, get_privilege_name, get_resource_name

try:
    from django.contrib.auth import get_user_model
    User = get_user_model()
except ImportError:
    from django.contrib.auth.models import User


class PermissionBackend(object):
    """Per object level permission backend."""
    supports_object_permissions = True
    supports_anonymous_user = True
    supports_inactive_user = True

    def authenticate(self, username, password):
        return None

    def has_perm(self, user, perm, obj=None):
        """This method checks if the user_obj has perm on obj. Returns True or False"""
        acl = get_acl()

        try:
            role = acl.get_role(get_role_name(user))
        except MissingRole:
            role = acl.add_role(get_role_name(user), user.groups.all().values_list('name', flat=True))
            if hasattr(user, 'simpleacl'):
                user.simpleacl(acl)

        privilege = acl.add_privilege(get_privilege_name(perm))

        resource = acl.add_resource(get_resource_name(obj))
        if obj is not None and hasattr(obj, 'simpleacl'):
            obj.simpleacl(acl, user, perm)

        try:
            return acl.is_allowed(role, privilege, resource)
        except (MissingRole, MissingPrivilege, MissingResource):
            raise
            return False
