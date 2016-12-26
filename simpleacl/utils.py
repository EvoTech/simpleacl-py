import c3linearize


def get_mro(current, bases_getter):
    return c3linearize.linearize(c3linearize.build_graph(current, bases_getter))[current]
