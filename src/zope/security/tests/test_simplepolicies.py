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
import unittest


class ConformsToIInteraction:

    def _getTargetClass(self):
        raise NotImplementedError("Subclass responsibility")

    def _makeOne(self, *participations):
        return self._getTargetClass()(*participations)

    def test_class_conforms_to_IInteraction(self):
        from zope.interface.verify import verifyClass

        from zope.security.interfaces import IInteraction
        verifyClass(IInteraction, self._getTargetClass())

    def test_instance_conforms_to_IInteraction(self):
        from zope.interface.verify import verifyObject

        from zope.security.interfaces import IInteraction
        verifyObject(IInteraction, self._makeOne())


class ParanoidSecurityPolicyTests(unittest.TestCase,
                                  ConformsToIInteraction,
                                  ):

    def _getTargetClass(self):
        from zope.security.simplepolicies import ParanoidSecurityPolicy
        return ParanoidSecurityPolicy

    def test_ctor_no_participations(self):
        policy = self._makeOne()
        self.assertEqual(policy.participations, [])

    def test_ctor_w_participations(self):
        class Participation:
            interaction = None
        p1, p2, p3 = Participation(), Participation(), Participation()
        policy = self._makeOne(p1, p2, p3)
        self.assertEqual(policy.participations, [p1, p2, p3])
        self.assertIs(p1.interaction, policy)
        self.assertIs(p2.interaction, policy)
        self.assertIs(p3.interaction, policy)

    def test_add_w_foreign_participation(self):
        class Participation:
            interaction = object()
        policy = self._makeOne()
        self.assertRaises(ValueError, policy.add, Participation())

    def test_remove_w_foreign_participation(self):
        class Participation:
            interaction = object()
        policy = self._makeOne()
        self.assertRaises(ValueError, policy.remove, Participation())

    def test_remove(self):
        class Participation:
            interaction = None
        p1, p2, p3 = Participation(), Participation(), Participation()
        policy = self._makeOne(p1, p2, p3)
        policy.remove(p2)

        self.assertEqual(policy.participations, [p1, p3])
        self.assertIs(p1.interaction, policy)
        self.assertIsNone(p2.interaction)
        self.assertIs(p3.interaction, policy)

    def test_checkPermission_w_public(self):
        from zope.security.checker import CheckerPublic
        policy = self._makeOne()
        target = object()
        self.assertTrue(policy.checkPermission(CheckerPublic, target))

    def test_checkPermission_w_non_public_only_system_user(self):
        from zope.security._definitions import system_user

        class Participation:
            interaction = None
            principal = system_user
        policy = self._makeOne(Participation())
        permission = object()
        target = object()
        self.assertTrue(policy.checkPermission(permission, target))

    def test_checkPermission_w_non_public_other_user(self):
        class Participation:
            interaction = None
            principal = object()
        policy = self._makeOne(Participation())
        permission = object()
        target = object()
        self.assertFalse(policy.checkPermission(permission, target))

    def test_checkPermission_w_no_participations(self):
        # The permission and object don't matter: if there are no
        # participations, access is allowed.
        policy = self._makeOne()
        self.assertTrue(policy.checkPermission(None, None))
        self.assertTrue(policy.checkPermission(self, self))


class PermissiveSecurityPolicyTests(unittest.TestCase,
                                    ConformsToIInteraction):

    def _getTargetClass(self):
        from zope.security.simplepolicies import PermissiveSecurityPolicy
        return PermissiveSecurityPolicy

    def test_checkPermission_w_public(self):
        policy = self._makeOne()
        permission = object()
        target = object()
        self.assertTrue(policy.checkPermission(permission, target))


def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
