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
        from zope.security.interfaces import IInteractionManagement
        from zope.security.interfaces import ISecurityManagement

        verifyObject(ISecurityManagement, management)
        verifyObject(IInteractionManagement, management)

    def test_securityPolicy(self):
        from zope.security.management import getSecurityPolicy
        from zope.security.management import setSecurityPolicy
        from zope.security.simplepolicies import PermissiveSecurityPolicy

        policy = PermissiveSecurityPolicy
        setSecurityPolicy(policy)
        self.assertTrue(getSecurityPolicy() is policy)

    def test_getInteraction_none_present(self):
        from zope.security.interfaces import NoInteraction
        from zope.security.management import getInteraction
        self.assertRaises(NoInteraction, getInteraction)

    def test_queryInteraction_none_present(self):
        from zope.security.management import queryInteraction
        self.assertEqual(queryInteraction(), None)

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
        self.assertEqual(queryInteraction(), None)

    def test_endInteraction_repeated(self):
        from zope.security.management import endInteraction
        from zope.security.management import newInteraction
        from zope.security.management import queryInteraction
        newInteraction()
        queryInteraction()
        endInteraction()
        self.assertEqual(queryInteraction(), None)
        endInteraction()
        self.assertEqual(queryInteraction(), None)

    def test_restoreInteraction_after_end(self):
        from zope.security.management import endInteraction
        from zope.security.management import newInteraction
        from zope.security.management import queryInteraction
        from zope.security.management import restoreInteraction
        newInteraction()
        interaction = queryInteraction()
        endInteraction()
        restoreInteraction()
        self.assertTrue(interaction is queryInteraction())

    def test_restoreInteraction_after_new(self):
        from zope.security.management import newInteraction
        from zope.security.management import queryInteraction
        from zope.security.management import restoreInteraction
        newInteraction()
        self.assertTrue(queryInteraction() is not None)
        restoreInteraction()  # restore to no interaction
        self.assertTrue(queryInteraction() is None)

    def test_restoreInteraction_after_neither(self):
        from zope.security._definitions import thread_local
        from zope.security.management import queryInteraction
        from zope.security.management import restoreInteraction
        try:
            del thread_local.interaction
        except AttributeError:
            pass
        try:
            del thread_local.previous_interaction
        except AttributeError:
            pass
        restoreInteraction()
        self.assertTrue(queryInteraction() is None)

    def test_checkPermission_w_no_interaction(self):
        from zope.security.interfaces import NoInteraction
        from zope.security.management import checkPermission
        permission = 'zope.Test'
        obj = object()
        self.assertRaises(NoInteraction, checkPermission, permission, obj)

    def test_checkPermission_w_interaction(self):
        from zope.security.management import checkPermission
        from zope.security.management import newInteraction
        from zope.security.management import queryInteraction
        from zope.security.management import setSecurityPolicy

        permission = 'zope.Test'
        obj = object()

        class PolicyStub:
            def checkPermission(s, p, o,):
                self.assertTrue(p is permission)
                self.assertTrue(o is obj)
                self.assertTrue(s is queryInteraction() or s is interaction)
                return s is interaction

        setSecurityPolicy(PolicyStub)
        newInteraction()
        interaction = queryInteraction()
        self.assertEqual(checkPermission(permission, obj), True)

    def test_checkPermission_forbidden_policy(self):
        from zope.security import checkPermission
        from zope.security.checker import CheckerPublic
        from zope.security.management import newInteraction
        from zope.security.management import setSecurityPolicy

        obj = object()

        class ForbiddenPolicyStub:
            def checkPermission(s, p, o):
                return False

        setSecurityPolicy(ForbiddenPolicyStub)
        newInteraction()
        self.assertEqual(checkPermission('zope.Test', obj), False)
        self.assertEqual(checkPermission(None, obj), True)
        self.assertEqual(checkPermission(CheckerPublic, obj), True)

    def test_system_user(self):
        from zope.interface.verify import verifyObject

        from zope.security.interfaces import IPrincipal
        from zope.security.interfaces import ISystemPrincipal
        from zope.security.management import system_user

        self.assertEqual(system_user.id,
                         'zope.security.management.system_user')

        self.assertEqual(system_user.title, 'System')

        for name in 'id', 'title', 'description':
            self.assertIsInstance(getattr(system_user, name),
                                  str)

        verifyObject(IPrincipal, system_user)
        verifyObject(ISystemPrincipal, system_user)


def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
