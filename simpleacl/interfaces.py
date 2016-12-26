
class IEntity(object):
    def __eq__(self, other):
        """
        :type other: simpleacl.interfaces.IEntity
        :rtype: bool
        """
        raise NotImplementedError

    def __ne__(self, other):
        """
        :type other: simpleacl.interfaces.IEntity
        :rtype: bool
        """
        raise NotImplementedError

    def __hash__(self):
        """
        :rtype: str
        """
        raise NotImplementedError

    def __bytes__(self):
        """
        :rtype: bytes
        """
        raise NotImplementedError

    def __str__(self):
        """
        :rtype: str
        """
        raise NotImplementedError

    def __repr__(self):
        """
        :rtype: str
        """
        raise NotImplementedError

    def get_name(self):
        """
        :rtype: str
        """
        raise NotImplementedError


class IRole(IEntity):
    pass


class IPrivilege(IEntity):
    pass


class IResource(IEntity):
    pass


class IBackend(object):
    pass


class IAcl(object):
    pass


class IRoleParentsWalker(object):
    def __call__(self, role, resource, acl):
        """
        :type role: simpleacl.interfaces.IRole
        :type resource: simpleacl.interfaces.IResource
        :type acl: simpleacl.interfaces.IAcl
        :rtype: tuple[simpleacl.interfaces.IRole]
        """
        raise NotImplementedError


class IAclWalker(object):
    def __call__(self, role, privilege, resource, acl):
        """
        :type role: simpleacl.interfaces.IRole
        :type privilege: simpleacl.interfaces.IPrivilege
        :type resource: simpleacl.interfaces.IResource
        :type acl: simpleacl.interfaces.IAcl
        :rtype: bool or None
        """
        raise NotImplementedError
