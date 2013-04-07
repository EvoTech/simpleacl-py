from __future__ import absolute_import, unicode_literals

INITIAL_DATA = {}

ACL_GETTER = 'simpleacl.paste.get_acl'

try:
    from simpleacl_settings import *
except ImportError:
    pass
