from __future__ import absolute_import, unicode_literals
"""
Example of usage.


class User(Model):
    # ...
    has_perm = user_has_perm


@register
def simpleacl_has_perm(user, perm, obj=None):
    model = type(obj)
    acl = get_acl()
    role = acl.add_role('user_{0}'.format(user.pk))
    privilege = acl.add_privilege(perm)
    resource = acl.add_resource(".".join((model.__module__, model.__name__, str(obj.pk))))
    return acl.is_allowed(role, privilege, resource) or False


@register
def obj_has_perm(user, perm, obj=None):
    if hasattr(obj, 'is_allowed'):
        try:
            return obj.is_allowed(user_obj, perm=perm)
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


def user_has_perm(user, perm, obj):
    for checker in register._registry:
        if checker(user, perm, obj):
            return True
    return False
