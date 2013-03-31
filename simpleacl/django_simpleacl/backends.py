# -*- mode: python; coding: utf-8; -*-
from __future__ import absolute_import, unicode_literals
from .utils import get_acl, get_role, get_privilege, get_context


class ObjectPermissionBackend(object):
    """Per object level permission backend."""
    supports_object_permissions = True
    supports_anonymous_user = True
    supports_inactive_user = True

    def authenticate(self, username, password):
        return None

    def has_perm(self, user, perm, obj=None):
        """This method checks if the user_obj has perm on obj.

        Returns True or False
        """
        if obj is None:
            return False

        try:
            return get_acl().is_allowed(
                get_role(user), get_privilege(perm), get_context(obj)
            )
        except:
            return False
