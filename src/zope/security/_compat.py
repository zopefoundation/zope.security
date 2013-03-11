##############################################################################
#
# Copyright (c) 2013 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
""" Python 2 / 3 compatibility
"""
import platform
import os
import sys
import types

py_impl = getattr(platform, 'python_implementation', lambda: None)
PYPY = py_impl() == 'PyPy'
PURE_PYTHON = os.environ.get('PURE_PYTHON', False)

if sys.version_info[0] < 3: #pragma NO COVER

    from StringIO import StringIO
    import cPickle as _pickle

    reload = reload

    def _u(s):
        return unicode(s, 'unicode_escape')

    CLASS_TYPES = (type, types.ClassType)
    _BUILTINS = '__builtin__'

    PYTHON3 = False
    PYTHON2 = True

    TEXT = unicode

else: #pragma NO COVER

    from io import StringIO
    import pickle as _pickle

    from imp import reload

    def _u(s):
        return s

    CLASS_TYPES = (type,)
    _BUILTINS = 'builtins'

    PYTHON3 = True
    PYTHON2 = False

    TEXT = str

_BLANK = _u('')
