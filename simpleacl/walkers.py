from simpleacl import interfaces, utils
from simpleacl.constants import ANY_PRIVILEGE, ANY_RESOURCE


class HierarchicalRoleParentsWalker(interfaces.IRoleParentsWalker):
    def __init__(self, parents_accessor, delegate):
        """
        :type parents_accessor: (simpleacl.interfaces.IRole, simpleacl.interfaces.IResource, simpleacl.interfaces.IAcl) -> tuple[simpleacl.interfaces.IResource]
        :type delegate: simpleacl.interfaces.IRoleParentsWalker
        """
        self._parents_accessor = parents_accessor
        self._delegate = delegate

    def __call__(self, role, resource, acl):
        """
        :type role: simpleacl.interfaces.IRole
        :type resource: simpleacl.interfaces.IResource
        :type acl: simpleacl.interfaces.IAcl
        :rtype: tuple[simpleacl.interfaces.IRole]
        """
        parent_roles = ()

        def bases_getter(current):
            return self._parents_accessor(role, current, acl)

        resource_bases = utils.get_mro(resource, bases_getter)
        for resource_base in resource_bases:
            parent_roles += self._delegate(role, resource_base, acl)
        return parent_roles


class SubstituteRoleParentsWalker(interfaces.IRoleParentsWalker):
    def __init__(self, substitute_accessor, delegate):
        """
        :type substitute_accessor: (simpleacl.interfaces.IRole, simpleacl.interfaces.IResource, simpleacl.interfaces.IAcl) -> tuple[simpleacl.interfaces.IResource]
        :type delegate: simpleacl.interfaces.IRoleParentsWalker
        """
        self._substitute_accessor = substitute_accessor
        self._delegate = delegate

    def __call__(self, role, resource, acl):
        """
        :type role: simpleacl.interfaces.IRole
        :type resource: simpleacl.interfaces.IResource
        :type acl: simpleacl.interfaces.IAcl
        :rtype: tuple[simpleacl.interfaces.IRole]
        """
        parent_roles = self._delegate(role, resource, acl)
        for substitute in self._substitute_accessor(role, resource, acl):
            if role != substitute:
                parent_roles += self._delegate(role, substitute, acl)
        return parent_roles


class CallRoleParentsWalker(interfaces.IRoleParentsWalker):
    def __init__(self, delegate):
        """
        :type delegate: simpleacl.interfaces.IRoleParentsWalker
        """
        self._delegate = delegate

    def __call__(self, role, resource, acl):
        """
        :type role: simpleacl.interfaces.IRole
        :type resource: simpleacl.interfaces.IResource
        :type acl: simpleacl.interfaces.IAcl
        :rtype: tuple[simpleacl.interfaces.IRole]
        """
        return self._delegate(role, resource, acl)


default_role_walker = SubstituteRoleParentsWalker(
    (lambda role, resource, acl: (acl.get_resource(ANY_RESOURCE),)),
    HierarchicalRoleParentsWalker(
        (lambda role, resource, acl: resource.get_parents()),
        HierarchicalRoleParentsWalker(
            (lambda role, resource, acl: (acl.get_resource(
                resource.get_name().rsplit('.', 1).pop(0)
            ),) if '.' in resource.get_name() else ()),
            (lambda role, resource, acl: role.get_plain_parents(resource, acl))
        )
    )
)


class HierarchicalAclWalker(interfaces.IAclWalker):
    def __init__(self, arg, parents_accessor, delegate):
        """
        :type arg: str
        :type parents_accessor: collections.Callable
        :type delegate: simpleacl.interfaces.IAclWalker
        """
        self._arg = arg
        self._parents_accessor = parents_accessor
        self._delegate = delegate

    def __call__(self, role, privilege, resource, acl):
        """
        :type role: simpleacl.interfaces.IRole
        :type privilege: simpleacl.interfaces.IPrivilege
        :type resource: simpleacl.interfaces.IResource
        :type acl: simpleacl.interfaces.IAcl
        :rtype: bool or None
        """
        kwargs = locals().copy()
        kwargs.pop('self')
        current = kwargs[self._arg]

        def bases_getter(current):
            new_kwargs = kwargs.copy()
            new_kwargs[self._arg] = current
            return self._parents_accessor(**new_kwargs)

        bases = utils.get_mro(current, bases_getter)
        for base in bases:
            new_kwargs = kwargs.copy()
            new_kwargs[self._arg] = base
            result = self._delegate(**new_kwargs)
            if result is not None:
                return result


class CompositeAclWalker(interfaces.IAclWalker):
    def __init__(self, *delegates):
        """
        :type delegates: list[simpleacl.interfaces.IAclWalker]
        """
        self._delegates = delegates

    def __call__(self, role, privilege, resource, acl):
        """
        :type role: simpleacl.interfaces.IRole
        :type privilege: simpleacl.interfaces.IPrivilege
        :type resource: simpleacl.interfaces.IResource
        :type acl: simpleacl.interfaces.IAcl
        :rtype: bool or None
        """
        for delegate in self._delegates:
            result = delegate(role, privilege, resource, acl)
            if result is not None:
                return result


class SubstituteAclWalker(interfaces.IAclWalker):
    def __init__(self, arg, substitute_accessor, delegate):
        """
        :type arg: str
        :type substitute_accessor: collections.Callable
        :type delegate: simpleacl.interfaces.IAclWalker
        """
        self._arg = arg
        self._substitute_accessor = substitute_accessor
        self._delegate = delegate

    def __call__(self, role, privilege, resource, acl):
        """
        :type role: simpleacl.interfaces.IRole
        :type privilege: simpleacl.interfaces.IPrivilege
        :type resource: simpleacl.interfaces.IResource
        :type acl: simpleacl.interfaces.IAcl
        :rtype: bool or None
        """
        kwargs = locals().copy()
        kwargs.pop('self')
        result = self._delegate(role, privilege, resource, acl)
        if result is not None:
            return result

        kwargs[self._arg] = self._substitute_accessor(**kwargs)
        return self._delegate(**kwargs)


class CallAclWalker(interfaces.IAclWalker):
    def __init__(self, delegate):
        """
        :type delegate: simpleacl.interfaces.IAclWalker
        """
        self._delegate = delegate

    def __call__(self, role, privilege, resource, acl):
        """
        :type role: simpleacl.interfaces.IRole
        :type privilege: simpleacl.interfaces.IPrivilege
        :type resource: simpleacl.interfaces.IResource
        :type acl: simpleacl.interfaces.IAcl
        :rtype: bool or None
        """
        return self._delegate(role, privilege, resource, acl)


default_acl_walker = HierarchicalAclWalker(
    'acl',
    (lambda role, privilege, resource, acl: (acl.parent,) if acl.parent else ()),
        HierarchicalAclWalker(
        'role',
        (lambda role, privilege, resource, acl: role.get_parents(resource, acl)),
        HierarchicalAclWalker(
            'role',
            (lambda role, privilege, resource, acl: (acl.get_role(
                role.get_name().rsplit('.', 1).pop(0)
            ),) if '.' in role.get_name() else ()),
            SubstituteAclWalker(
                'resource',
                (lambda role, privilege, resource, acl: acl.get_resource(ANY_RESOURCE)),
                HierarchicalAclWalker(
                    'resource',
                    (lambda role, privilege, resource, acl: resource.get_parents()),
                    HierarchicalAclWalker(
                        'resource',
                        (lambda role, privilege, resource, acl: (acl.get_resource(
                            resource.get_name().rsplit('.', 1).pop(0)
                        ),) if '.' in resource.get_name() else ()),
                        SubstituteAclWalker(
                            'privilege',
                            (lambda role, privilege, resource, acl: acl.get_privilege(ANY_PRIVILEGE)),
                            HierarchicalAclWalker(
                                'privilege',
                                (lambda role, privilege, resource, acl: (acl.get_privilege(
                                    privilege.get_name().rsplit('.', 1).pop(0)
                                ),) if '.' in privilege.get_name() else ()),
                                CallAclWalker(
                                    (lambda role, privilege, resource, acl: acl.is_plain_allowed(role, privilege, resource))
                                )
                            )
                        )
                    )
                )
            )
        )
    )
)
