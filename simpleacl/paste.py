from __future__ import absolute_import, unicode_literals
import sys
import inspect
from threading import local
from . import settings
from . import Acl, ANY_RESOURCE

try:
    str = unicode  # Python 2.* compatible
    string_types = (basestring,)
    integer_types = (int, long)
except NameError:
    string_types = (str,)
    integer_types = (int,)

"""
Example of usage.


class User(Model):
    # ...
    has_perm = user_has_perm


@register
def simpleacl_has_perm(user, perm, obj=None):
        acl = get_acl()

        try:
            role = acl.get_role(get_role_name(user))
        except MissingRole:
            role = acl.add_role(get_role_name(user), user.groups.all().values_list('name', flat=True))
            if hasattr(user, '__simpleacl__'):
                user.__simpleacl__(acl)

        privilege = acl.add_privilege(get_privilege_name(perm))

        resource = acl.add_resource(get_resource_name(obj))
        if obj is not None and hasattr(obj, '__simpleacl__'):
            obj.__simpleacl__(acl, user, perm)

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


def user_has_perm(user, perm, obj=None):
    for checker in register._registry:
        if checker(user, perm, obj):
            return True
    return False


def get_acl(thread_safe=True):
    ctx = thread_safe and _ctx or _dummy
    try:
        return ctx.acl
    except AttributeError:
        ctx.acl = Acl.create_instance(settings.INITIAL_DATA)
    return ctx.acl


def get_role_name(user):
    """User(pk=15, ) -> user_15"""
    return 'user_{0}'.format(getattr(user, 'pk', 0))


def get_resource_name(obj):
    """blog.Post(pk=15, ) -> blog.post.15"""
    if obj is None:
        return ANY_RESOURCE
    if not inspect.isclass(obj):
        model = type(obj)
        return ".".join((model.__module__, model.__name__, str(obj.pk))).lower()
    return ".".join((obj.__module__, obj.__name__)).lower()


def resolve(str_or_obj):
    """Returns object from string"""
    if not isinstance(str_or_obj, string_types):
        return str_or_obj
    if '.' not in str_or_obj:
        str_or_obj += '.'
    mod_name, obj_name = str_or_obj.rsplit('.', 1)
    __import__(mod_name)
    mod = sys.modules[mod_name]
    return getattr(mod, obj_name) if obj_name else mod


if settings.ACL_GETTER != 'simpleacl.paste.get_acl':
    get_acl = resolve(settings.ACL_GETTER)
