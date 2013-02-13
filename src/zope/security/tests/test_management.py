##############################################################################
#
# Copyright (c) 2001, 2002 Zope Foundation and Contributors.
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
""" Unit tests for zope.security.management
"""
import unittest


class Test(unittest.TestCase):

    def setUp(self):
        self._cleanUp()

    def tearDown(self):
        self._cleanUp()

    def _cleanUp(self):
        from zope.security.management import _clear
        from zope.security.management import endInteraction
        _clear()
        endInteraction()

    def test_import(self):
        from zope.interface.verify import verifyObject
        from zope.security import management
        from zope.security.interfaces import ISecurityManagement
        from zope.security.interfaces import IInteractionManagement

        verifyObject(ISecurityManagement, management)
        verifyObject(IInteractionManagement, management)

    def test_securityPolicy(self):
        from zope.security.management import setSecurityPolicy
        from zope.security.management import getSecurityPolicy
        from zope.security.simplepolicies import PermissiveSecurityPolicy

        policy = PermissiveSecurityPolicy
        setSecurityPolicy(policy)
        self.assert_(getSecurityPolicy() is policy)

    def test_getInteraction_none_present(self):
        from zope.security.interfaces import NoInteraction
        from zope.security.management import getInteraction
        self.assertRaises(NoInteraction, getInteraction)

    def test_queryInteraction_none_present(self):
        from zope.security.management import queryInteraction
        self.assertEquals(queryInteraction(), None)

    def test_newInteraction(self):
        from zope.security.management import newInteraction
        from zope.security.management import queryInteraction
        newInteraction()
        interaction = queryInteraction()
        self.assertTrue(interaction is not None)

    def test_newInteraction_repeated_without_end(self):
        from zope.security.management import ExistingInteraction
        from zope.security.management import newInteraction
        newInteraction()
        self.assertRaises(ExistingInteraction, newInteraction)

    def test_endInteraction(self):
        from zope.security.management import endInteraction
        from zope.security.management import newInteraction
        from zope.security.management import queryInteraction
        newInteraction()
        endInteraction()
        self.assertEquals(queryInteraction(), None)

    def test_endInteraction_repeated(self):
        from zope.security.management import endInteraction
        from zope.security.management import newInteraction
        from zope.security.management import queryInteraction
        newInteraction()
        interaction = queryInteraction()
        endInteraction()
        self.assertEquals(queryInteraction(), None)
        endInteraction()
        self.assertEquals(queryInteraction(), None)

    def test_restoreInteraction_after_end(self):
        from zope.security.management import endInteraction
        from zope.security.management import newInteraction
        from zope.security.management import queryInteraction
        from zope.security.management import restoreInteraction
        newInteraction()
        interaction = queryInteraction()
        endInteraction()
        restoreInteraction()
        self.assert_(interaction is queryInteraction())

    def test_restoreInteraction_after_new(self):
        from zope.security.management import newInteraction
        from zope.security.management import queryInteraction
        from zope.security.management import restoreInteraction
        newInteraction()
        self.assert_(queryInteraction() is not None)
        restoreInteraction() # restore to no interaction
        self.assert_(queryInteraction() is None)

    def test_restoreInteraction_after_neither(self):
        from zope.security.management import queryInteraction
        from zope.security.management import restoreInteraction
        from zope.security._definitions import thread_local
        try:
            del thread_local.interaction
        except AttributeError:
            pass
        try:
            del thread_local.previous_interaction
        except AttributeError:
            pass
        restoreInteraction()
        self.assert_(queryInteraction() is None)

    def test_checkPermission_w_no_interaction(self):
        from zope.security.management import checkPermission
        from zope.security.interfaces import NoInteraction
        permission = 'zope.Test'
        obj = object()
        self.assertRaises(NoInteraction, checkPermission, permission, obj)

    def test_checkPermission_w_interaction(self):
        from zope.security.management import checkPermission
        from zope.security.management import setSecurityPolicy
        from zope.security.management import queryInteraction
        from zope.security.management import newInteraction

        permission = 'zope.Test'
        obj = object()

        class PolicyStub(object):
            def checkPermission(s, p, o,):
                self.assert_(p is permission)
                self.assert_(o is obj)
                self.assert_(s is queryInteraction() or s is interaction)
                return s is interaction

        setSecurityPolicy(PolicyStub)
        newInteraction()
        interaction = queryInteraction()
        self.assertEquals(checkPermission(permission, obj), True)

    def test_checkPermission_forbidden_policy(self):
        from zope.security import checkPermission
        from zope.security.checker import CheckerPublic
        from zope.security.management import setSecurityPolicy
        from zope.security.management import newInteraction

        obj = object()

        class ForbiddenPolicyStub(object):
            def checkPermission(s, p, o):
                return False

        setSecurityPolicy(ForbiddenPolicyStub)
        newInteraction()
        self.assertEquals(checkPermission('zope.Test', obj), False)
        self.assertEquals(checkPermission(None, obj), True)
        self.assertEquals(checkPermission(CheckerPublic, obj), True)

    def test_system_user(self):
        from zope.security.management import system_user
        from zope.security._compat import TEXT
        from zope.security._compat import _u
        self.assertEquals(system_user.id,
                          _u('zope.security.management.system_user'))

        self.assertEquals(system_user.title, _u('System'))

        for name in 'id', 'title', 'description':
            self.assert_(isinstance(getattr(system_user, name), TEXT))

def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(Test),
    ))
