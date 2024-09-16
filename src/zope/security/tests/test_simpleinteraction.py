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
"""Unit tests for zope.security.simpleinteraction.
"""
import unittest


class RequestStub:

    def __init__(self, principal=None):
        self.principal = principal
        self.interaction = None


class TestInteraction(unittest.TestCase):

    def test(self):
        from zope.interface.verify import verifyObject

        from zope.security.interfaces import IInteraction
        from zope.security.simplepolicies import ParanoidSecurityPolicy
        interaction = ParanoidSecurityPolicy()
        verifyObject(IInteraction, interaction)

    def test_add(self):
        from zope.security.simplepolicies import ParanoidSecurityPolicy
        rq = RequestStub()
        interaction = ParanoidSecurityPolicy()
        interaction.add(rq)
        self.assertIn(rq, interaction.participations)
        self.assertIs(rq.interaction, interaction)

        # rq already added
        self.assertRaises(ValueError, interaction.add, rq)

        interaction2 = ParanoidSecurityPolicy()
        self.assertRaises(ValueError, interaction2.add, rq)

    def test_remove(self):
        from zope.security.simplepolicies import ParanoidSecurityPolicy
        rq = RequestStub()
        interaction = ParanoidSecurityPolicy()

        self.assertRaises(ValueError, interaction.remove, rq)

        interaction.add(rq)

        interaction.remove(rq)
        self.assertNotIn(rq, interaction.participations)
        self.assertIsNone(rq.interaction)

    def testCreateInteraction(self):
        from zope.interface.verify import verifyObject

        from zope.security.interfaces import IInteraction
        from zope.security.simplepolicies import ParanoidSecurityPolicy
        i1 = ParanoidSecurityPolicy()
        verifyObject(IInteraction, i1)
        self.assertEqual(list(i1.participations), [])

        user = object()
        request = RequestStub(user)
        i2 = ParanoidSecurityPolicy(request)
        verifyObject(IInteraction, i2)
        self.assertEqual(list(i2.participations), [request])


def test_suite():
    return unittest.TestSuite((
        unittest.defaultTestLoader.loadTestsFromTestCase(TestInteraction),
    ))
