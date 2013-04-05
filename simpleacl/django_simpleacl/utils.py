from __future__ import absolute_import, unicode_literals
import inspect
from .. import ANY_RESOURCE


def get_role_name(user):
    """User(pk=15, ) -> user_15"""
    return 'user_{0}'.format(user.pk)


def get_privilege_name(name):
    """blog.add_post -> blog.post.add"""
    app, action = name.rsplit('.', 1)
    action, mod = action.rsplit('_', 1)
    return '.'.join([app, mod, action])


def get_resource_name(obj):
    """Post(pk=15, ) -> blog.post.15"""
    if obj is None:
        return ANY_RESOURCE
    if not inspect.isclass(obj):
        return '.'.join(obj._meta.app_label, obj._meta.module_name, str(obj.pk))
    return '.'.join(obj._meta.app_label, obj._meta.module_name)
