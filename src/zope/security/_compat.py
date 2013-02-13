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
import sys
import types

if sys.version_info[0] < 3: #pragma NO COVER

    def _u(s):
        return unicode(s, 'unicode_escape')

    CLASS_TYPES = (type, types.ClassType)

    PYTHON3 = False
    PYTHON2 = True

else: #pragma NO COVER

    def _u(s):
        return s

    CLASS_TYPES = (type,)

    PYTHON3 = True
    PYTHON2 = False

_BLANK = _u('')
