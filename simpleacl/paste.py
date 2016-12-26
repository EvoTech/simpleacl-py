from __future__ import absolute_import, unicode_literals
import inspect
from threading import local
from simpleacl import acl, settings, utils
from simpleacl.constants import ANY_RESOURCE

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
            if hasattr(user, 'simpleacl'):
                user.simpleacl(acl)

        privilege = acl.add_privilege(get_privilege_name(perm))

        resource = acl.add_resource(get_resource_name(obj))
        if obj is not None and hasattr(obj, 'simpleacl'):
            obj.simpleacl(acl, user, perm)

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
        ctx.acl = acl.Acl.create_instance(settings.INITIAL_DATA)
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


if settings.ACL_GETTER != 'simpleacl.paste.get_acl':
    get_acl = utils.resolve(settings.ACL_GETTER)
