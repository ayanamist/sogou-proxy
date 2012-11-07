"""Miscellaneous utility functions."""

from __future__ import absolute_import, division


# Fake byte literal support:  In python 2.6+, you can say b"foo" to get
# a byte literal (str in 2.x, bytes in 3.x).  There's no way to do this
# in a way that supports 2.5, though, so we need a function wrapper
# to convert our string literals.  b() should only be applied to literal
# latin1 strings.  Once we drop support for 2.5, we can remove this function
# and just use byte literals.
if str is unicode:
    def b(s):
        return s.encode('latin1')
    bytes_type = bytes
else:
    def b(s):
        return s
    bytes_type = str


def raise_exc_info(exc_info):
    """Re-raise an exception (with original traceback) from an exc_info tuple.

    The argument is a ``(type, value, traceback)`` tuple as returned by
    `sys.exc_info`.
    """
    # 2to3 isn't smart enough to convert three-argument raise
    # statements correctly in some cases.
    if isinstance(exc_info[1], exc_info[0]):
        raise exc_info[1], None, exc_info[2]
        # After 2to3: raise exc_info[1].with_traceback(exc_info[2])
    else:
        # I think this branch is only taken for string exceptions,
        # which were removed in Python 2.6.
        raise exc_info[0], exc_info[1], exc_info[2]
        # After 2to3: raise exc_info[0](exc_info[1]).with_traceback(exc_info[2])


def doctests():
    import doctest
    return doctest.DocTestSuite()
