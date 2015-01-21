from __future__ import absolute_import, unicode_literals
import unittest

if __name__ == '__main__':
    import os
    import sys
    sys.path.insert(0, os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    ))

import simpleacl
from simpleacl.exceptions import MissingRole, MissingPrivilege
from simpleacl import json


class TestSimpleAcl(unittest.TestCase):

    def setUp(self):
        self.acl = simpleacl.Acl()

    def tearDown(self):
        self.acl = None

    def test_role_gets_added(self):
        self.acl.add_role('role1')
        self.assertTrue(len(self.acl._backend._roles) > 0)

    def test_role_object_gets_added(self):
        role = simpleacl.Role('role1')
        self.acl.add_role(role)
        self.assertTrue(len(self.acl._backend._roles) > 0)

    def test_only_role_objects_and_strings_get_added(self):
        self.assertRaises(
            Exception,
            self.acl.add_role,
            dict(a='b')
        )

    def test_privilege_gets_added(self):
        self.acl.add_privilege('privilege1')
        self.assertTrue(len(self.acl._backend._privileges) > 0)

    def test_privilege_object_gets_added(self):
        privilege = simpleacl.Privilege('privilege1')
        self.acl.add_privilege(privilege)
        self.assertTrue(len(self.acl._backend._privileges) > 0)

    def test_only_privilege_objects_and_strings_get_added(self):
        self.assertRaises(
            Exception,
            self.acl.add_privilege,
            dict(a='b')
        )

    def test_role_stored_is_role_object(self):
        self.acl.add_role('role1')
        self.assertTrue(isinstance(self.acl.get_role('role1'), simpleacl.Role))

    def test_privilege_stored_is_privilege_object(self):
        self.acl.add_privilege('privilege1')
        self.assertTrue(
            isinstance(self.acl.get_privilege('privilege1'),
                       simpleacl.Privilege)
        )

    def test_cant_set_to_missing_role(self):
        self.assertRaises(
            MissingRole,
            self.acl.get_role,
            'role999'
        )

    def test_role_is_allowed(self):
        self.acl.add_role('role1')
        self.acl.add_role('role2')
        self.acl.add_privilege('privilege1')
        self.acl.add_privilege('privilege2')
        self.acl.allow('role1', 'privilege2')
        self.assertTrue(self.acl.is_allowed('role1', 'privilege2'))
        self.assertTrue(self.acl.get_bound_role('role1').is_allowed('privilege2'))
        self.assertTrue(self.acl.is_allowed(simpleacl.Role('role1'), simpleacl.Privilege('privilege2')))

    def test_role_is_not_allowed(self):
        self.acl.add_role('role1')
        self.acl.add_role('role2')
        self.acl.add_privilege('privilege1')
        self.acl.add_privilege('privilege2')
        self.acl.allow('role1', 'privilege2')
        self.assertTrue(not self.acl.is_allowed('role1', 'privilege1'))

    def test_cant_allow_missing_roles(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('privilege2')
        self.assertRaises(
            MissingRole,
            self.acl.allow,
            'role222',
            'privilege2'
        )

    def test_cant_allow_missing_privileges(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('privilege1')
        self.assertRaises(
            MissingPrivilege,
            self.acl.allow,
            'role1',
            'privilege222'
        )

    def test_allow_role_to_all_privileges(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('r1')
        self.acl.add_privilege('r2')
        self.acl.add_privilege('r3')
        self.acl.allow('role1', 'any')
        self.assertTrue(self.acl.is_allowed('role1', 'r1'))
        self.assertTrue(self.acl.is_allowed('role1', 'r2'))
        self.assertTrue(self.acl.is_allowed('role1', 'r3'))

    def test_ignores_on_double_allow(self):
        self.acl.add_role('role1')
        self.acl.add_privilege('r1')
        self.acl.add_privilege('r2')
        self.acl.allow('role1', 'r1')
        self.acl.allow('role1', 'r1')

    def test_parent_acl(self):
        self.acl.add_role('staff')
        self.acl.add_role('admin', ('staff',))
        self.acl.add_privilege('p1')
        self.acl.add_privilege('p2')
        self.acl.add_resource('r1')
        self.acl.add_resource('r2')
        self.acl.allow('staff', 'p1', 'r1')
        subacl = simpleacl.Acl()
        subacl.parent = self.acl
        subacl.add_role('user1', ['admin'])
        subacl.add_role('user2')
        subacl.allow('user2', 'p2', 'r2')
        self.assertTrue(subacl.is_allowed('user1', 'p1', 'r1'))
        self.assertFalse(subacl.is_allowed('user2', 'p1', 'r1'))
        self.assertFalse(subacl.is_allowed('user1', 'p2', 'r1'))
        self.assertFalse(subacl.is_allowed('user1', 'p1', 'r2'))
        self.assertTrue(subacl.is_allowed('user2', 'p2', 'r2'))

    def test_object_creation_from_json(self):
        test_dict = {
            'roles': ['superuser', ['user_1', ['superuser', ], ], 'user_2', ],
            'privileges': ['browse.blog.post', 'view.blog.post', 'add.blog.post', 'edit.blog.post', 'delete.blog.post', ],
            'resources': ['blog.post.1', 'blog.post.2', ],
            'acl': {
                'any': {'superuser': {'any': True}},
                'blog.post.2': {'user_2': {'view.blog.post': True}},
            }
        }
        test_json = json.dumps(test_dict)
        acl = simpleacl.Acl.create_instance(test_json)
        self.assertTrue(isinstance(acl, simpleacl.Acl))
        self.assertTrue(acl.is_allowed('user_2', 'view.blog.post', 'blog.post.2'))
        self.assertFalse(acl.is_allowed('user_2', 'edit.blog.post', 'blog.post.2'))
        self.assertFalse(acl.is_allowed('user_2', 'view.blog.post', 'blog.post.1'))

        self.assertTrue(acl.is_allowed('user_1', 'view.blog.post', 'blog.post.2'))
        self.assertTrue(acl.is_allowed('user_1', 'edit.blog.post', 'blog.post.2'))
        self.assertTrue(acl.is_allowed('user_1', 'view.blog.post', 'blog.post.1'))

    def test_object_creation_from_json2(self):
        test_dict = {
            'roles': [
                'moderator',
                'author',
                'authenticated',
                ['user_1', {'any': ['authenticated'],
                            'blog': ['moderator']}],
                ['user_2', {'any': ['authenticated'],
                            'blog.post.2': ['author']}],
                ['user_3', {'any': ['authenticated'],
                            'blog.post.2': ['moderator']}],
            ],
            'privileges': [
                'browse.blog.post',
                'view.blog.post',
                'add.blog.post',
                'edit.blog.post',
                'delete.blog.post',
            ],
            'resources': ['blog.post.1', 'blog.post.2', 'blog.post.3', 'board.message.3'],
            'acl': {
                'any': {
                    'authenticated': {'browse.blog.post': True},
                },
                'blog.post': {
                    'moderator': {'browse': True,
                                  'view': True,
                                  'edit': True},
                    'author': {'browse.blog.post': True,
                               'view.blog.post': True,
                               'edit.blog.post': True},
                }
            }
        }
        test_json = json.dumps(test_dict)
        acl = simpleacl.Acl.create_instance(test_json)
        self.assertTrue(isinstance(acl, simpleacl.Acl))
        self.assertTrue(acl.is_allowed('user_2', 'browse.blog.post', 'blog.post.2'))
        self.assertTrue(acl.is_allowed('user_2', 'view.blog.post', 'blog.post.2'))
        self.assertTrue(acl.is_allowed('user_2', 'edit.blog.post', 'blog.post.2'))
        self.assertFalse(acl.is_allowed('user_2', 'delete.blog.post', 'blog.post.2'))
        self.assertFalse(acl.is_allowed('user_2', 'edit.blog.post', 'blog.post'))
        self.assertFalse(acl.is_allowed('user_2', 'edit.blog', 'blog.post'))

        self.assertTrue(acl.is_allowed('user_2', 'browse.blog.post', 'blog.post.1'))
        self.assertFalse(acl.is_allowed('user_2', 'edit.blog.post', 'blog.post.1'))

        self.assertTrue(acl.is_allowed('user_1', 'view.blog.post', 'blog.post.2'))
        self.assertTrue(acl.is_allowed('user_1', 'edit.blog.post', 'blog.post.2'))
        self.assertTrue(acl.is_allowed('user_1', 'edit.blog.post', 'blog.post.1'))
        self.assertTrue(acl.is_allowed('user_1', 'edit.blog.post', 'blog.post'))
        self.assertTrue(acl.is_allowed('user_1', 'edit.blog', 'blog.post.2'))
        self.assertTrue(acl.is_allowed('user_1', 'edit.blog', 'blog.post'))
        self.assertTrue(acl.is_allowed('user_1', 'view.blog.post', 'blog.post.1'))
        self.assertFalse(acl.is_allowed('user_1', 'view', 'blog'))
        self.assertFalse(acl.is_allowed('user_1', 'view', 'board.message.3'))

        self.assertTrue(acl.is_allowed('user_3', 'edit.blog.post', 'blog.post.2'))
        self.assertFalse(acl.is_allowed('user_3', 'edit.blog.post', 'blog.post.3'))
        self.assertFalse(acl.is_allowed('user_3', 'edit.blog.post', 'blog.post'))
        self.assertFalse(acl.is_allowed('user_3', 'edit.blog.post', 'blog'))

if __name__ == '__main__':
    unittest.main()
