from __future__ import absolute_import, unicode_literals
import inspect
from threading import local
from . import Acl, ANY_RESOURCE

"""
Example of usage.


class User(Model):
    # ...
    has_perm = user_has_perm


@register
def simpleacl_has_perm(user, perm, obj=None):
    acl = get_acl()
    role = acl.add_role(get_role_name(user))
    privilege = acl.add_privilege(perm)
    resource = acl.add_resource(get_resource_name(obj))
    return acl.is_allowed(role, privilege, resource) or False


@register
def obj_has_perm(user, perm, obj=None):
    if hasattr(obj, 'is_allowed'):
        try:
            return obj.is_allowed(user, perm=perm)
        except Exception:
            pass
    return False
"""


class Registry(object):
    """Registry checkers"""

    def __init__(self):
        self._registry = []

    def __call__(self, func):
        self._registry.append(func)
        return func

register = Registry()


class DummyCtx(object):
    pass

_ctx = local()
_dummy = DummyCtx()


def user_has_perm(user, perm, obj):
    for checker in register._registry:
        if checker(user, perm, obj):
            return True
    return False


def get_acl(thread_safe=True):
    ctx = thread_safe and _ctx or _dummy
    try:
        from simpleacl_settings import INITIAL_DATA
    except ImportError:
        INITIAL_DATA = {}

    try:
        return ctx.acl
    except AttributeError:
        ctx.acl = Acl.create_instance(INITIAL_DATA)
    return ctx.acl


def get_role_name(user):
    """User(pk=15, ) -> user_15"""
    return 'user_{0}'.format(user.pk)


def get_resource_name(obj):
    """blog.Post(pk=15, ) -> blog.post.15"""
    if obj is None:
        return ANY_RESOURCE
    if not inspect.isclass(obj):
        model = type(obj)
        return ".".join((model.__module__, model.__name__, str(obj.pk))).lower()
    return ".".join((obj.__module__, obj.__name__)).lower()
