#######################################################################
# Simpleacl - A small access control list
# Copyright (C) 2010  Ivan Zakrevsky <ivzak [at] yandex [dot] ru>
# Copyright (C) 2010  Kyle Terry <kyle [at] fiverlabs [dot] com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#######################################################################
from __future__ import absolute_import, unicode_literals

import collections
from functools import partial
from simpleacl import exceptions, interfaces, walkers, utils
from simpleacl.constants import ANY_PRIVILEGE, ANY_RESOURCE

try:
    import simplejson as json
except ImportError:
    import json

try:
    str = unicode  # Python 2.* compatible
    string_types = (basestring,)
    integer_types = (int, long)
except NameError:
    string_types = (str,)
    integer_types = (int,)


class Entity(interfaces.IEntity):
    """Abstract class"""

    def __init__(self, name):
        self.name = name

    def __eq__(self, other):
        return self.name.__eq__(getattr(other, 'name', other))

    def __ne__(self, other):
        return self.name.__ne__(getattr(other, 'name', other))

    def __hash__(self):
        return self.name.__hash__()

    def __bytes__(self):
        return str(self.name).encode('utf-8')

    def __str__(self):
        return str(self.name)

    def __repr__(self):
        return b'<{0}: {1}>'.format(type(self).__name__, self.__bytes__())

    def get_name(self):
        return self.name


class Role(Entity, interfaces.IRole):
    """Holds a role value"""

    def __init__(self, name, walker=None):
        self.name = name
        self._parents = collections.defaultdict(list)  # Order is important, so use the list(), not set
        self._walk = walker or walkers.default_role_walker

    def add_parent(self, parent, resource):
        parents = self._parents.setdefault(resource, [])
        if parent not in parents:
            parents.append(parent)

    def get_parents(self, resource, acl):
        return self._walk(self, resource, acl)

    def get_plain_parents(self, resource, acl):
        return tuple(self._parents[resource])


class BoundRole(Entity, interfaces.IRole):

    def __init__(self, role, acl):
        self.name = role.name
        self.role = role
        self.acl = acl

    def __getattr__(self, name):
        if name in ('is_allowed', 'allow', 'remove_allow', 'remove_rule',
                    'deny', 'add_rule', 'remove_rule', ):
            return partial(getattr(self.acl, name), self.role)
        raise AttributeError


class Privilege(Entity, interfaces.IPrivilege):
    """Holds a privilege value"""
    pass


class Resource(Entity, interfaces.IResource):
    """Holds a role value"""

    def __init__(self, name):
        """For example, name == 'blog.post.15'.

        You can create a subclass, and override this method
        to obtain name from model.
        """
        self.name = name
        self._parents = []  # Order is important, so use the list(), not set

    def add_parent(self, parent):
        if parent not in self._parents:
            self._parents.append(parent)

    def get_parents(self):
        return self._parents

    def get_object(self):
        """Returns loadable resource object.

        For example, load model by path 'blog.post.15'.
        """
        raise NotImplementedError


class SimpleBackend(interfaces.IBackend):
    """A simple storage."""

    role_class = Role
    privilege_class = Privilege
    resource_class = Resource

    def __init__(self):
        """Constructor."""
        self._roles = {}
        self._privileges = {}
        self._acl = {}
        self._resources = {}

    def add_role(self, instance):
        """Adds role"""
        self._roles[instance.get_name()] = instance

    def get_role(self, name):
        """Returns a role instance"""
        try:
            return self._roles[name]
        except KeyError:
            raise exceptions.MissingRole('Missing Role "{0}"'.format(name))

    def add_privilege(self, instance):
        """Adds privilege"""
        self._privileges[instance.get_name()] = instance

    def get_privilege(self, name):
        """Returns a privilege instance"""
        try:
            return self._privileges[name]
        except KeyError:
            raise exceptions.MissingPrivilege('Missing Privilege "{0}"'.format(name))

    def add_resource(self, instance):
        """Adds privilege"""
        self._resources[instance.get_name()] = instance

    def get_resource(self, name):
        """Returns a privilege instance"""
        try:
            return self._resources[name]
        except KeyError:
            raise exceptions.MissingResource('Missing Resource "{0}"'.format(name))

    def add_rule(self, role, privilege, resource, allow=True):
        """Adds rule to the ACL"""
        self._acl.setdefault(resource, {}).setdefault(role, {})[privilege] = allow
        return self

    def remove_rule(self, role, privilege, resource, allow=True):
        """Removes rule from ACL"""
        try:
            if self._acl[resource][role][privilege] == allow:
                del self._acl[resource][role][privilege]
        except KeyError:
            pass
        return self

    def is_allowed(self, role, privilege, resource, undef=None):
        """Returns True if role is allowed for given arguments"""
        try:
            return self._acl[resource][role][privilege]
        except KeyError:
            return undef


class Acl(interfaces.IAcl):
    """Access control list."""

    def __init__(self, backend_factory=SimpleBackend, walker=None):
        """Constructor."""
        self.parent = None
        self._backend = backend_factory()
        self._walk = walker or walkers.default_acl_walker
        self.add_privilege(ANY_PRIVILEGE)
        self.add_resource(ANY_RESOURCE)

    def add_role(self, name_or_instance, parents=()):
        """Adds a role to the ACL"""
        if isinstance(name_or_instance, self._backend.role_class):
            instance = name_or_instance
        elif isinstance(name_or_instance, string_types):
            try:
                instance = self.get_role(name_or_instance)
            except exceptions.MissingRole:
                instance = self._backend.role_class(name_or_instance)
        else:
            raise Exception('Unknown role type: {0}'.format(type(name_or_instance).__name__))
        self._backend.add_role(instance)

        # Parents support
        if type(parents) != dict:
            parents = {ANY_RESOURCE: parents}
        for resource, parent_list in parents.items():
            for parent in parent_list:
                resource = self.get_resource(resource)
                parent = self.add_role(parent)
                instance.add_parent(parent, resource)

        # Hierarchical support
        if '.' in instance.get_name():
            parent = instance.get_name().rsplit('.', 1).pop(0)
            parent = self.add_role(parent)  # Recursive
        return instance

    def get_role(self, name_or_instance):
        """Returns the identified role instance"""
        if isinstance(name_or_instance, self._backend.role_class):
            instance = name_or_instance
        else:
            try:
                instance = self._backend.get_role(name_or_instance)
            except exceptions.MissingRole:
                if self.parent is None:
                    raise
                return self.parent.get_role(name_or_instance)
        return instance

    def get_bound_role(self, name_or_instance):
        return BoundRole(self.get_role(name_or_instance), self)

    def add_privilege(self, name_or_instance):
        """Adds a privilege to the ACL"""
        if isinstance(name_or_instance, self._backend.privilege_class):
            instance = name_or_instance
        elif isinstance(name_or_instance, string_types):
            try:
                instance = self.get_privilege(name_or_instance)
            except exceptions.MissingPrivilege:
                instance = self._backend.privilege_class(name_or_instance)
        else:
            raise Exception('Unknown privilege type: {0}'.format(type(name_or_instance).__name__))
        self._backend.add_privilege(instance)

        # Hierarchical support
        if '.' in instance.get_name():
            parent = instance.get_name().rsplit('.', 1).pop(0)
            parent = self.add_privilege(parent)  # Recursive
        return self.get_privilege(instance)

    def get_privilege(self, name_or_instance):
        """Returns the identified privilege instance"""
        if isinstance(name_or_instance, self._backend.privilege_class):
            return name_or_instance
        try:
            return self._backend.get_privilege(name_or_instance)
        except exceptions.MissingPrivilege:
            if self.parent is None:
                raise
            return self.parent.get_privilege(name_or_instance)

    def add_resource(self, name_or_instance, parents=()):
        """Adds a privilege to the ACL"""
        if isinstance(name_or_instance, self._backend.privilege_class):
            instance = name_or_instance
        elif isinstance(name_or_instance, string_types):
            try:
                instance = self.get_resource(name_or_instance)
            except exceptions.MissingResource:
                instance = self._backend.resource_class(name_or_instance)
        else:
            raise Exception('Unknown privilege type: {0}'.format(type(name_or_instance).__name__))
        self._backend.add_resource(instance)

        # Parents support
        for parent in parents:
            parent = self.add_resource(parent)
            instance.add_parent(parent)

        # Hierarchical support
        if '.' in instance.get_name():
            parent = instance.get_name().rsplit('.', 1).pop(0)
            parent = self.add_resource(parent)  # Recursive
        return self.get_resource(instance)

    def get_resource(self, name_or_instance):
        """Returns the identified privilege instance"""
        if isinstance(name_or_instance, self._backend.resource_class):
            return name_or_instance
        try:
            return self._backend.get_resource(name_or_instance)
        except exceptions.MissingResource:
            if self.parent is None:
                raise
            return self.parent.get_resource(name_or_instance)

    def add_rule(self, role, privileges=ANY_PRIVILEGE, resource=ANY_RESOURCE, allow=True):
        """Adds rule to the ACL"""
        if not is_list(privileges):
            privileges = (privileges, )
        for priv in privileges:
            self._backend.add_rule(self.get_role(role), self.get_privilege(priv), self.get_resource(resource), allow)
        return self

    def remove_rule(self, role, privileges=ANY_PRIVILEGE, resource=ANY_RESOURCE, allow=True):
        """Removes rule from ACL"""
        if not is_list(privileges):
            privileges = (privileges, )
        for priv in privileges:
            self._backend.remove_rule(self.get_role(role), self.get_privilege(priv), self.get_resource(resource), allow)
        return self

    def allow(self, role, privileges=ANY_PRIVILEGE, resource=ANY_RESOURCE):
        """Adds an "allow" rule to the ACL"""
        return self.add_rule(role, privileges, resource, True)

    def remove_allow(self, role, privileges=ANY_PRIVILEGE, resource=ANY_RESOURCE):
        """Removes an "allow" rule from the ACL"""
        return self.remove_rule(role, privileges, resource, True)

    def deny(self, role, privileges=ANY_PRIVILEGE, resource=ANY_RESOURCE):
        """Adds a "deny" rule to the ACL"""
        return self.add_rule(role, privileges, resource, False)

    def remove_deny(self, role, privileges=ANY_PRIVILEGE, resource=ANY_RESOURCE):
        """Removes a "deny" rule from the ACL"""
        return self.remove_rule(role, privileges, resource, False)

    def is_allowed(self, role, privilege, resource=ANY_RESOURCE, undef=False):
        """Returns True if role is allowed for given privilege in given given resource"""
        if resource is None:
            resource = ANY_RESOURCE
        role = self.get_role(role)
        privilege = self.get_privilege(privilege)
        resource = self.get_resource(resource)
        allow = self._walk(role, privilege, resource, self)
        if allow is not None:
            return allow
        return undef

    def is_plain_allowed(self, role, privilege, resource):
        allow = self._backend.is_allowed(role, privilege, resource, None)
        if allow is not None:
            if isinstance(allow, string_types) and '.' in allow:
                allow = utils.resolve(allow)
                if isinstance(allow, collections.Callable):
                    allow = allow(self, role, privilege, resource)
        return allow

    def bulk_load(self, json_or_dict, resource=ANY_RESOURCE):
        """You can store your roles, privileges and allow list (many to many)
        in a json encoded string and pass it into this method to build
        the object without having to call add_role or add_privilege for each
        one.
        """
        if isinstance(json_or_dict, bytes):
            json_or_dict = str(json_or_dict)
        if isinstance(json_or_dict, str):
            clean = json.loads(json_or_dict)
        else:
            clean = json_or_dict

        for value in clean.get('resources', ()):
            if is_list(value):
                self.add_resource(*value)
            elif isinstance(value, dict):
                self.add_resource(**value)
            else:
                self.add_resource(value)

        for value in clean.get('roles', ()):
            if is_list(value):
                self.add_role(*value)
            elif isinstance(value, dict):
                self.add_role(**value)
            else:
                self.add_role(value)

        for value in clean.get('privileges', ()):
            self.add_privilege(value)

        for resource, resource_rules in clean.get('acl', {}).items():
            for role, role_rules in resource_rules.items():
                for privilege, allow in role_rules.items():
                    self.add_rule(role, privilege, resource, allow)
        return self

    @classmethod
    def create_instance(cls, json_or_dict):
        """You can store your roles, privileges and allow list (many to many)
        in a json encoded string and pass it into this method to build
        the object without having to call add_role or add_privilege for each
        one.
        """
        obj = cls()
        obj.bulk_load(json_or_dict)
        return obj


def is_list(v):
    return isinstance(v, (list, tuple))


# Python 2.* compatible
try:
    unicode
except NameError:
    pass
else:
    for cls in (Entity,):
        cls.__unicode__ = cls.__str__
        cls.__str__ = lambda self: self.__unicode__().encode('utf-8')
