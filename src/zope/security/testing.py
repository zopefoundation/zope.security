##############################################################################
#
# Copyright (c) 2004-2011 Zope Foundation and Contributors.
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
"""
Testing support code.

This module provides some helper/stub objects for setting up interactions.
"""
import contextlib
import re

from zope.testing import renormalizing

import zope.security.management
from zope import component
from zope import interface
from zope.security import interfaces
from zope.security._compat import PYTHON2 as PY2
from zope.security.interfaces import PUBLIC_PERMISSION_NAME
from zope.security.permission import Permission


_str_prefix = 'b' if PY2 else 'u'

rules = [
    (re.compile(_str_prefix + "('.*?')"), r"\1"),
    (re.compile(_str_prefix + '(".*?")'), r"\1"),
]
output_checker = renormalizing.RENormalizing(rules)


@interface.implementer(interfaces.IPrincipal)
class Principal(object):
    """
    A trivial implementation of :class:`zope.security.interfaces.IPrincipal`.
    """

    def __init__(self, id, title=None, description='', groups=None):
        self.id = id
        self.title = title or id
        self.description = description
        if groups is not None:
            self.groups = groups
            interface.directlyProvides(self, interfaces.IGroupAwarePrincipal)


@interface.implementer(interfaces.IParticipation)
class Participation(object):
    """
    A trivial implementation of
    :class:`zope.security.interfaces.IParticipation`.
    """

    def __init__(self, principal):
        self.principal = principal
        self.interaction = None


def addCheckerPublic():
    """
    Add the CheckerPublic permission as :data:`zope.Public
    <zope.security.interfaces.PUBLIC_PERMISSION_NAME>`.
    """

    perm = Permission(
        PUBLIC_PERMISSION_NAME,
        'Public',
        """Special permission used for resources that are always public

        The public permission is effectively an optimization, sine
        it allows security computation to be bypassed.
        """
    )
    gsm = component.getGlobalSiteManager()
    gsm.registerUtility(perm, interfaces.IPermission, perm.id)

    return perm


def create_interaction(principal_id, **kw):
    """
    Create a new interaction for the given principal ID, make it the
    :func:`current interaction
    <zope.security.management.newInteraction>`, and return the
    :class:`Principal` object.
    """
    principal = Principal(principal_id, **kw)
    participation = Participation(principal)
    zope.security.management.newInteraction(participation)
    return principal


@contextlib.contextmanager
def interaction(principal_id, **kw):
    """
    A context manager for running an interaction for the given
    principal ID.
    """
    if zope.security.management.queryInteraction():
        # There already is an interaction. Great. Leave it alone.
        yield
    else:
        principal = create_interaction(principal_id, **kw)
        try:
            yield principal
        finally:
            zope.security.management.endInteraction()
