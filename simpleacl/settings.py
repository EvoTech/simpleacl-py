from __future__ import absolute_import, unicode_literals
import os

INITIAL_DATA = {}

ACL_GETTER = 'simpleacl.paste.get_acl'

try:
    m = __import__(os.getenv('SIMPLEACL_SETTINGS', 'simpleacl_settings'))
except ImportError:
    pass
else:
    for key in dir(m):
        if key[0] != '_':
            globals()[key] = getattr(m, key)
