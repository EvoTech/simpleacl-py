from __future__ import absolute_import, unicode_literals
from threading import local
from .. import Acl, ALL_CONTEXTS


class DummyCtx(object):
    pass

_ctx = local()
_dummy = DummyCtx()


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


def get_role(user):
    """User(pk=15, ) -> user_15"""
    return 'user_{0}'.format(user.pk)


def get_privilege(name):
    """blog.add_post -> blog.post.add"""
    app, action = name.rsplit('.', 1)
    action, mod = action.rsplit('_', 1)
    return '.'.join([app, mod, action])


def get_context(obj):
    """Post(pk=15, ) -> blog.post.15"""
    if obj is None:
        return ALL_CONTEXTS
    return '{app}.{mod}.{pk}'.format(
        app=obj._meta.app_label,
        mod=obj._meta.module_name,
        pk=obj.pk
    )
