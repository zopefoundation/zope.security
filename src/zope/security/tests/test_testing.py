#############################################################################
#
# Copyright (c) 2011 Zope Foundation and Contributors.
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

from zope.testing.cleanup import CleanUp

from zope.security import testing
from zope.security.interfaces import PUBLIC_PERMISSION_NAME as zope_Public


class TestTestingFunctions(CleanUp,
                           unittest.TestCase):

    def test_create_interaction_should_return_principal(self):
        from zope.security.management import getInteraction

        principal = testing.create_interaction(
            'foo', groups=['bar'], description='desc')
        ix = getInteraction()
        participation = ix.participations[0]
        self.assertEqual('foo', participation.principal.id)
        self.assertEqual(principal.groups, participation.principal.groups)
        self.assertEqual('desc', participation.principal.description)

    def test_usable_as_contextmanager(self):
        from zope.security.management import getInteraction
        from zope.security.management import queryInteraction

        with testing.interaction('foo'):
            ix = getInteraction()
            participation = ix.participations[0]
            self.assertEqual('foo', participation.principal.id)
            # Nesting doesn't change anything
            with testing.interaction('baz'):
                ix = getInteraction()
                participation = ix.participations[0]
                self.assertEqual('foo', participation.principal.id)

        self.assertFalse(queryInteraction())

    def test_contextmanager_ends_interaction_on_exception(self):
        from zope.security.management import queryInteraction

        class MyError(Exception):
            pass

        with self.assertRaises(MyError):
            with testing.interaction('foo'):
                raise MyError()

        self.assertFalse(queryInteraction())

    def test_addCheckerPublic(self):
        from zope import component
        from zope.security.interfaces import IPermission

        perm = testing.addCheckerPublic()
        utility = component.getUtility(IPermission, name=zope_Public)
        self.assertIs(perm, utility)


def test_suite():
    return unittest.defaultTestLoader.loadTestsFromName(__name__)
