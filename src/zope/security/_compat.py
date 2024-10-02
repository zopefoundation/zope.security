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
import os
import platform


py_impl = getattr(platform, 'python_implementation', lambda: None)
PYPY = py_impl() == 'PyPy'
PURE_PYTHON = int(os.environ.get('PURE_PYTHON', PYPY))


class implementer_if_needed:
    # Helper to make sure we don't redundantly implement interfaces
    # already inherited. Doing so tends to produce problems with the
    # C3 order. Even though here we could easily statically determine
    # if we need the interface or not, this is used for clarity, to
    # reduce the testing load, and to insulate against changes in
    # super classes.
    def __init__(self, *ifaces):
        self._ifaces = ifaces

    def __call__(self, cls):
        from zope.interface import implementedBy
        from zope.interface import implementer

        ifaces_needed = []
        implemented = implementedBy(cls)
        ifaces_needed = [
            iface
            for iface in self._ifaces
            if not implemented.isOrExtends(iface)
        ]
        return implementer(*ifaces_needed)(cls)
