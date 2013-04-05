from __future__ import absolute_import, unicode_literals


class AclEcxeption(Exception):

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class MissingRole(AclEcxeption):
    pass


class MissingPrivilege(AclEcxeption):
    pass


class MissingResource(AclEcxeption):
    pass


class PermissionDenied(AclEcxeption):
    pass
