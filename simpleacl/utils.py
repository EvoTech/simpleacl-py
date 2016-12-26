import sys
import c3linearize

try:
    str = unicode  # Python 2.* compatible
    string_types = (basestring,)
    integer_types = (int, long)
except NameError:
    string_types = (str,)
    integer_types = (int,)


def get_mro(current, bases_getter):
    return c3linearize.linearize(c3linearize.build_graph(current, bases_getter))[current]


def resolve(str_or_obj):
    """Returns object from string"""
    if not isinstance(str_or_obj, string_types):
        return str_or_obj
    if '.' not in str_or_obj:
        str_or_obj += '.'
    mod_name, obj_name = str_or_obj.rsplit('.', 1)
    __import__(mod_name)
    mod = sys.modules[mod_name]
    return getattr(mod, obj_name) if obj_name else mod
