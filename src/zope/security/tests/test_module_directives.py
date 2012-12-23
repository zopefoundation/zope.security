##############################################################################
#
# Copyright (c) 2003 Zope Foundation and Contributors.
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
"""Directives Tests
"""
import unittest


def _skip_wo_zope_configuration(testfunc):
    try:
        import zope.configuration.xmlconfig
    except ImportError:
        from functools import update_wrapper
        def dummy(self):
            pass
        update_wrapper(dummy, testfunc)
        return dummy
    else:
        return testfunc


@_skip_wo_zope_configuration
def make_dummy():
    from zope.interface import Interface
    import zope.security.zcml
    global IDummy
    class IDummy(Interface):
        perm = zope.security.zcml.Permission(title=u'')


perms = []

def dummy(context_, perm):
    global perms
    perms.append(perm)


class DirectivesTest(unittest.TestCase):

    def setUp(self):
        try:
            from zope.component.testing import setUp
        except ImportError:
            pass
        else:
            setUp()

    def tearDown(self):
        del perms[:]
        try:
            from zope.component.testing import tearDown
        except ImportError:
            pass
        else:
            tearDown()

    @_skip_wo_zope_configuration
    def testRedefinePermission(self):
        from zope.configuration import xmlconfig
        from zope.security import tests
        make_dummy()
        xmlconfig.file("redefineperms.zcml", tests)
        self.assertEqual(perms, ['zope.Security'])

def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(DirectivesTest),
    ))
