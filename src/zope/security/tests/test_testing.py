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


class InteractionHelperTest(unittest.TestCase):

    def tearDown(self):
        from zope.security.management import endInteraction
        endInteraction()

    def test_create_interaction_should_return_principal(self):
        from zope.security.management import getInteraction
        from zope.security.testing import create_interaction
        principal = create_interaction(
            'foo', groups=['bar'], description='desc')
        ix = getInteraction()
        participation = ix.participations[0]
        self.assertEqual('foo', participation.principal.id)
        self.assertEqual(principal.groups, participation.principal.groups)
        self.assertEqual('desc', participation.principal.description)

    def test_usable_as_contextmanager(self):
        from zope.security.management import getInteraction
        from zope.security.management import queryInteraction
        from zope.security.testing import interaction
        with interaction('foo'):
            ix = getInteraction()
            participation = ix.participations[0]
            self.assertEqual('foo', participation.principal.id)
        self.assertFalse(queryInteraction())

    def test_contextmanager_ends_interaction_on_exception(self):
        from zope.security.management import queryInteraction
        from zope.security.testing import interaction
        try:
            with interaction('foo'):
                raise RuntimeError()
        except RuntimeError:
            pass
        self.assertFalse(queryInteraction())


def test_suite():
    return unittest.TestSuite((
        unittest.makeSuite(InteractionHelperTest),
    ))
