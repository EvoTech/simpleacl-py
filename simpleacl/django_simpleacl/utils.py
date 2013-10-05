from __future__ import absolute_import, unicode_literals
import inspect
from .. import ANY_RESOURCE
from ..paste import get_acl


def add_rule(user, perm, obj=None, allow=True):
    acl = get_acl()
    role = acl.add_role(get_role_name(user))
    privilege = acl.add_privilege(get_privilege_name(perm))
    resource = acl.add_resource(get_resource_name(obj))
    return acl.add_rule(role, privilege, resource, allow)


def allow(user, perm, obj=None):
    return add_rule(user, perm, obj, allow=True)


def deny(user, perm, obj=None):
    return add_rule(user, perm, obj, allow=False)


def get_role_name(user):
    """User(pk=15, ) -> user_15"""
    return 'user_{0}'.format(getattr(user, 'pk', 0))


def get_privilege_name(name):
    """blog.add_post -> blog.post.add"""
    # Maybe better add.blog.post ?
    try:
        app, action = name.rsplit('.', 1)
        action, mod = action.rsplit('_', 1)
        return '.'.join([app, mod, action])
    except ValueError:
        return name


def get_resource_name(obj):
    """Post(pk=15, ) -> blog.post.15"""
    if obj is None:
        return ANY_RESOURCE
    if not inspect.isclass(obj):
        return '.'.join((obj._meta.app_label, obj._meta.module_name, str(obj.pk)))
    return '.'.join((obj._meta.app_label, obj._meta.module_name))
