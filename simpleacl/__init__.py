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
try:
    import simplejson as json
except:
    import json

from simpleacl.exceptions import MissingRole, MissingPrivilege, MissingContext

try:
    str = unicode  # Python 2.* compatible
except NameError:
    pass
    

ALL_PRIVILEGES = 'all'
ALL_CONTEXTS = 'all'


class Role(object):
    """Holds a role value"""

    _parents = []  # Order is important, so use the list(), not set

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

    def get_name(self):
        return self.name

    def add_parent(self, parent):
        if parent not in self._parents:
            self._parents.append(parent)

    def get_parents(self):
        return self._parents


class Privilege(object):
    """Holds a privilege value"""

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

    def get_name(self):
        return self.name


class Context(object):
    """Holds a role value"""

    _parents = []  # Order is important, so use the list(), not set

    def __init__(self, name):
        """For example, name == 'blog.post.15'.

        You can create a subclass, and override this method
        to obtain name from model."""
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

    def get_name(self):
        return self.name

    def add_parent(self, parent):
        if parent not in self._parents:
            self._parents.append(parent)

    def get_parents(self):
        return self._parents

    def get_object(self):
        """Returns downloadable context object.

        For example, load model by path 'blog.post.15'.
        """
        raise NotImplementedError


class SimpleBackend(object):
    """A simple storage."""

    role_class = Role
    privilege_class = Privilege
    context_class = Context

    def __init__(self):
        """Constructor."""
        self._roles = {}
        self._privileges = {}
        self._acl = {}
        self._contexts = {}

    def add_role(self, instance, parents=()):
        """Adds role"""
        self._roles.setdefault(instance.get_name(), instance)
        return self

    def get_role(self, name):
        """Returns a role instance"""
        try:
            return self._roles[name]
        except KeyError:
            raise MissingRole(
                'Role must be added before requested.'
            )

    def add_privilege(self, instance):
        """Adds privilege"""
        self._privileges.setdefault(instance.get_name(), instance)
        return self

    def get_privilege(self, name):
        """Returns a privilege instance"""
        try:
            return self._privileges[name]
        except KeyError:
            raise MissingPrivilege(
                'Privilege must be added before requested.'
            )

    def add_context(self, instance, parents=()):
        """Adds privilege"""
        self._contexts.setdefault(instance.get_name(), instance)
        return self

    def get_context(self, name):
        """Returns a privilege instance"""
        try:
            return self._contexts[name]
        except KeyError:
            raise MissingContext(
                'Context must be added before requested.'
            )

    def add_rule(self, role, privilege=ALL_PRIVILEGES,
                 context=ALL_CONTEXTS, allow=True):
        """Adds rule to the ACL"""
        self._acl.setdefault(context, {}).setdefault(role, {})[privilege] = allow
        return self

    def remove_rule(self, role, privilege=ALL_PRIVILEGES,
                    context=None, allow=True):
        """Removes rule from ACL"""
        try:
            if self._acl[context][role][privilege] == allow:
                del self._acl[context][role][privilege]
        except KeyError:
            pass
        return self

    def role_has_privilege(self, role, privilege, context=None, allow=True):
        """Removes rule from ACL"""
        try:
            return self._acl[context][role][privilege] == allow
        except KeyError:
            return False

    def is_allowed(self, role, privilege, context=None, undef=None):
        """Returns True if role is allowed

        for given privilege in given given context
        """
        try:
            return self._acl[context][role][privilege]
        except KeyError:
            return undef


class Acl(object):
    """Access control list."""

    def __init__(self, backend_class=SimpleBackend):
        """Constructor."""
        self._backend = backend_class()
        self.add_privilege(ALL_PRIVILEGES)
        self.add_context(ALL_CONTEXTS)

    def add_role(self, name_or_instance, parents=()):
        """Adds a role to the ACL"""
        if isinstance(name_or_instance, bytes):
            name_or_instance = str(name_or_instance)
        if isinstance(name_or_instance, str):
            instance = self._backend.role_class(name_or_instance)
        elif isinstance(name_or_instance, self._backend.role_class):
            instance = name_or_instance
        else:
            raise Exception(
                'Unable to add a role of type: {0}'\
                    .format(type(name_or_instance).__name__)
            )
        self._backend.add_role(instance)

        # Parents support for roles
        for parent in parents:
            parent = self.add_role(parent)
            instance.add_parent(parent)

        # Hierarchical support for roles
        if '.' in instance.get_name():
            parent = instance.get_name().rsplit('.', 1).pop(0)
            parent = self.add_role(parent)  # Recursive
        return instance

    def get_role(self, name_or_instance):
        """Returns the identified role instance"""
        if isinstance(name_or_instance, self._backend.role_class):
            return name_or_instance
        return self._backend.get_role(name_or_instance)

    def add_privilege(self, name_or_instance):
        """Adds a privilege to the ACL"""
        if isinstance(name_or_instance, bytes):
            name_or_instance = str(name_or_instance)
        if isinstance(name_or_instance, str):
            instance = self._backend.privilege_class(name_or_instance)
        elif isinstance(name_or_instance, self._backend.privilege_class):
            instance = name_or_instance
        else:
            raise Exception(
                'Unable to add a privilege of type: {0}'\
                    .format(type(name_or_instance).__name__)
            )
        self._backend.add_privilege(instance)

        # Hierarchical support for instances
        if '.' in instance.get_name():
            parent = instance.get_name().rsplit('.', 1).pop(0)
            parent = self.add_privilege(parent)  # Recursive
        return instance

    def get_privilege(self, name_or_instance):
        """Returns the identified privilege instance"""
        if isinstance(name_or_instance, bytes):
            name_or_instance = str(name_or_instance)
        if isinstance(name_or_instance, str):
            return self._backend.get_privilege(name_or_instance)
        if isinstance(name_or_instance, self._backend.privilege_class):
            return name_or_instance
        raise Exception(
            'Unable to get a Privelege of type: {0}'\
                .format(type(name_or_instance).__name__)
        )

    def add_context(self, name_or_instance, parents=()):
        """Adds a privilege to the ACL"""
        if isinstance(name_or_instance, bytes):
            name_or_instance = str(name_or_instance)
        if isinstance(name_or_instance, str):
            instance = self._backend.context_class(name_or_instance)
        elif isinstance(name_or_instance, self._backend.privilege_class):
            instance = name_or_instance
        else:
            raise Exception(
                'Unable to add a privilege of type: {0}'\
                    .format(type(name_or_instance).__name__)
            )
        self._backend.add_context(instance)

        # Parents support for roles
        for parent in parents:
            parent = self.add_context(parent)
            instance.add_parent(parent)
        return instance

    def get_context(self, name_or_instance):
        """Returns the identified privilege instance"""
        if isinstance(name_or_instance, bytes):
            name_or_instance = str(name_or_instance)
        if isinstance(name_or_instance, str):
            return self._backend.get_context(name_or_instance)
        if isinstance(name_or_instance, self._backend.context_class):
            return name_or_instance
        raise Exception(
            'Unable to get a Privelege of type: {0}'\
                .format(type(name_or_instance).__name__)
        )

    def add_rule(self, role, privileges=ALL_PRIVILEGES,
                 context=ALL_CONTEXTS, allow=True):
        """Adds rule to the ACL"""
        if not hasattr(privileges, '__iter__'):
            privileges = (privileges, )
        for priv in privileges:
            self._backend.add_rule(
                self.get_role(role), self.get_privilege(priv), self.get_context(context), allow
            )
        return self

    def remove_rule(self, role, privileges=ALL_PRIVILEGES,
                    context=ALL_CONTEXTS, allow=True):
        """Removes rule from ACL"""
        if not hasattr(privileges, '__iter__'):
            privileges = (privileges, )
        for priv in privileges:
            self._backend.remove_rule(
                self.get_role(role), self.get_privilege(priv), self.get_context(context), allow
            )
        return self

    def allow(self, role, privileges=ALL_PRIVILEGES, context=ALL_CONTEXTS):
        """Adds an "allow" rule to the ACL"""
        return self.add_rule(role, privileges, context, True)

    def remove_allow(self, role, privileges=ALL_PRIVILEGES, context=ALL_CONTEXTS):
        """Removes an "allow" rule from the ACL"""
        return self.remove_rule(role, privileges, context, True)

    def deny(self, role, privileges=ALL_PRIVILEGES, context=ALL_CONTEXTS):
        """Adds a "deny" rule to the ACL"""
        return self.add_rule(role, privileges, context, False)

    def remove_deny(self, role, privileges=ALL_PRIVILEGES, context=ALL_CONTEXTS):
        """Removes a "deny" rule from the ACL"""
        return self.remove_rule(role, privileges, context, False)

    def role_has_privilege(self, role, privilege, context=ALL_CONTEXTS, allow=True):
        """Returns True if role has privilege"""
        try:
            return self._backend.role_has_privilege(
                self.get_role(role), self.get_privilege(privilege),
                self.get_context(context), allow
            )
        except MissingPrivilege:
            return False

    def is_allowed(self, role, privilege, context=ALL_CONTEXTS, undef=False):
        """Returns True if role is allowed

        for given privilege in given given context
        """
        if context is None:
            context = ALL_CONTEXTS

        role = self.get_role(role)
        privilege = self.get_privilege(privilege)
        context = self.get_context(context)

        allow = self._backend.is_allowed(role, privilege, context, None)
        if allow is not None:
            return allow

        # Parents support for roles
        for parent in role.get_parents():
            allow = self.is_allowed(parent, privilege, context, None)
            if allow is not None:
                return allow

        # Hierarchical support for roles
        if '.' in role.get_name():
            parent = self.get_role(role.get_name().rsplit('.', 1).pop(0))
            allow = self.is_allowed(parent, privilege, context, None)
            if allow is not None:
                return allow

        # Hierarchical support for privileges
        if '.' in privilege.get_name():
            parent = self.get_privilege(
                privilege.get_name().rsplit('.', 1).pop(0)
            )
            allow = self.is_allowed(role, parent, context, None)
            if allow is not None:
                return allow

        # Parents support for context
        for parent in context.get_parents():
            allow = self.is_allowed(role, privilege, parent, None)
            if allow is not None:
                return allow

        # Checks for global context or privilege
        if privilege.get_name() !=  ALL_PRIVILEGES:
            allow = self.is_allowed(role, ALL_PRIVILEGES, context, None)
            if allow is not None:
                return allow

        if context.get_name() != ALL_CONTEXTS:
            allow = self.is_allowed(role, privilege, ALL_CONTEXTS, None)
            if allow is not None:
                return allow

        if privilege.get_name() != ALL_PRIVILEGES and context.get_name() != ALL_CONTEXTS:
            allow = self._backend.is_allowed(role, ALL_PRIVILEGES, ALL_CONTEXTS, None)
            if allow is not None:
                return allow

        return undef

    def bulk_load(self, json_or_dict, context=ALL_CONTEXTS):
        """You can store your roles, privileges and allow list (many to many)
        in a json encoded string and pass it into this method to build
        the object without having to call add_role or add_privilege for each
        one. TODO: make better documentation for this method.
        """
        if isinstance(json_or_dict, bytes):
            json_or_dict = str(json_or_dict)
        if isinstance(json_or_dict, str):
            clean = json.loads(json_or_dict)
        else:
            clean = json_or_dict

        for value in clean.get('roles', ()):
            if hasattr(value, '__iter__'):
                self.add_role(*value)
            elif isinstance(value, dict):
                self.add_role(**value)
            else:
                self.add_role(value)

        for value in clean.get('privileges', ()):
            self.add_privilege(value)

        for value in clean.get('contexts', ()):
            if hasattr(value, '__iter__'):
                self.add_context(*value)
            elif isinstance(value, dict):
                self.add_context(**value)
            else:
                self.add_role(value)

        for row in clean.get('acl', ()):
            self.allow(row['role'], row['privilege'],
                       row.get(context, context), row['allow'])
        return self

    @classmethod
    def create_instance(cls, json_or_dict):
        """You can store your roles, privileges and allow list (many to many)
        in a json encoded string and pass it into this method to build
        the object without having to call add_role or add_privilege for each
        one. TODO: make better documentation for this method.
        """
        obj = cls()
        obj.bulk_load(json_or_dict)
        return obj

# Python 2.* compatible
try:
    unicode
except NameError:
    pass
else:
    for cls in (Role, Privilege, Context, ):
        cls.__unicode__ = cls.__str__
        cls.__str__ = cls.__bytes__
